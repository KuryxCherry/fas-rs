/*
 * Copyright (c) 2024 shadow3aaa@gitbub.com
 *
 * This file is part of frame-analyzer-ebpf.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::{env, fs, path::Path, process::Command};

use anyhow::{Result, bail};

fn main() -> Result<()> {
    let extra_bin = ensure_ebpf_linker()?;
    build_ebpf(extra_bin.as_deref())?;
    Ok(())
}

fn add_path(add: Option<&Path>) -> Result<String> {
    let path = env::var("PATH")?;
    match add {
        Some(dir) => Ok(format!("{}:{path}", dir.display())),
        None => Ok(path),
    }
}

fn ensure_ebpf_linker() -> Result<Option<std::path::PathBuf>> {
    if Command::new("bpf-linker")
        .arg("--version")
        .status()
        .is_ok_and(|s| s.success())
    {
        return Ok(None);
    }

    let out_dir = env::var("OUT_DIR")?;
    let out_dir = Path::new(&out_dir);
    let target_dir = out_dir.join("temp_target");
    let target_dir_str = target_dir.to_str().unwrap();

    let status = Command::new("cargo")
        .args([
            "install",
            "bpf-linker",
            "--force",
            "--root",
            target_dir_str,
            "--target-dir",
            target_dir_str,
        ])
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .status()?;

    if !status.success() {
        bail!("Failed to install bpf-linker (exit status: {status})");
    }

    Ok(Some(target_dir.join("bin")))
}

fn build_ebpf(extra_bin: Option<&Path>) -> Result<()> {
    let current_dir = env::current_dir()?;
    let project_path = current_dir.parent().unwrap().join("frame-analyzer-ebpf");
    let out_dir = env::var("OUT_DIR")?;
    let out_dir = Path::new(&out_dir);
    let target_dir = out_dir.join("ebpf_target");
    let target_dir_str = target_dir.to_str().unwrap();

    if !target_dir.exists() {
        fs::create_dir_all(&target_dir)?;
    }

    #[allow(unused_mut)]
    let mut ebpf_args = vec![
        "build",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--target-dir",
        target_dir_str,
    ];

    println!("cargo:rerun-if-changed=../frame-analyzer-ebpf");
    println!("cargo:rerun-if-changed=../frame-analyzer-ebpf-common");

    #[cfg(not(debug_assertions))]
    ebpf_args.push("--release");

    let status = Command::new("cargo")
        .args(ebpf_args)
        .current_dir(&project_path)
        .env("PATH", add_path(extra_bin)?)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("CC")
        .env_remove("CXX")
        .env_remove("AR")
        .env_remove("CFLAGS")
        .env_remove("CXXFLAGS")
        .env_remove("LDFLAGS")
        .status()?;

    if !status.success() {
        bail!("Failed to build frame-analyzer-ebpf (exit status: {status})");
    }

    Ok(())
}
