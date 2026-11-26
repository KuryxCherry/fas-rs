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
use std::num::NonZeroU32;

use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
    programs::{
        UProbe,
        uprobe::{UProbeAttachLocation, UProbeScope},
    },
};

use crate::{
    ebpf::load_bpf,
    error::{AnalyzerError, Result},
};

const LIBGUI_PATH: &str = "/system/lib64/libgui.so";

const QUEUE_BUFFER_SYMBOLS: &[&str] = &[
    // Android 12 - 15: android::Surface::queueBuffer(ANativeWindowBuffer*, int)
    "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferi",
    // Android 15 - 16: android::Surface::queueBuffer(ANativeWindowBuffer*, int, SurfaceQueueBufferOutput*)
    "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferiPNS_24SurfaceQueueBufferOutputE",
    // Android 17+: android::Surface::hook_queueBuffer(ANativeWindow*, ANativeWindowBuffer*, int)
    "_ZN7android7Surface16hook_queueBufferEP13ANativeWindowP19ANativeWindowBufferi",
    // Android 17+: android::Surface::queueBufferImpl(sp<GraphicBuffer> const&, sp<Fence> const&, SurfaceQueueBufferInput const*, SurfaceQueueBufferOutput*)
    "_ZN7android7Surface15queueBufferImplERKNS_2spINS_13GraphicBufferEEERKNS1_INS_5FenceEEEPKNS_23SurfaceQueueBufferInputEPNS_24SurfaceQueueBufferOutputE",
    // Android 17+: android::Surface::queueBuffer(sp<GraphicBuffer> const&, sp<Fence> const&, SurfaceQueueBufferOutput*)
    "_ZN7android7Surface11queueBufferERKNS_2spINS_13GraphicBufferEEERKNS1_INS_5FenceEEEPNS_24SurfaceQueueBufferOutputE",
    // Android 17+: android::Surface::queueBuffer(sp<GraphicBuffer> const&, SurfaceQueueBufferInput const*, SurfaceQueueBufferOutput*)
    "_ZN7android7Surface11queueBufferERKNS_2spINS_13GraphicBufferEEERKNS_23SurfaceQueueBufferInputEPNS_24SurfaceQueueBufferOutputE",
];

pub struct UprobeHandler {
    bpf: Ebpf,
}

impl Drop for UprobeHandler {
    fn drop(&mut self) {
        if let Ok(program) = self.get_program() {
            let _ = program.unload();
        }
    }
}

impl UprobeHandler {
    pub fn attach_app(pid: i32) -> Result<Self> {
        let pid_u32 = u32::try_from(pid)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(AnalyzerError::AppNotFound)?;
        let scope = UProbeScope::OneProcess(pid_u32);

        let mut bpf = load_bpf()?;

        let program: &mut UProbe = bpf.program_mut("frame_analyzer_ebpf").unwrap().try_into()?;
        program.load()?;

        let mut last_err = None;
        for symbol in QUEUE_BUFFER_SYMBOLS {
            match program.attach([UProbeAttachLocation::Symbol(symbol)], LIBGUI_PATH, scope) {
                Ok(_) => return Ok(Self { bpf }),
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap().into())
    }

    pub fn ring(&mut self) -> Result<RingBuf<&mut MapData>> {
        let ring: RingBuf<&mut MapData> = RingBuf::try_from(self.bpf.map_mut("RING_BUF").unwrap())?;
        Ok(ring)
    }

    fn get_program(&mut self) -> Result<&mut UProbe> {
        let program: &mut UProbe = self
            .bpf
            .program_mut("frame_analyzer_ebpf")
            .unwrap()
            .try_into()?;
        Ok(program)
    }
}
