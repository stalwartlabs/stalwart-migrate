/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
pub struct TerminalMode(libc::termios);

impl TerminalMode {
    pub fn capture() -> Option<Self> {
        let mut saved = MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, saved.as_mut_ptr()) } != 0 {
            return None;
        }
        Some(TerminalMode(unsafe { saved.assume_init() }))
    }

    pub fn restore(&self) -> bool {
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0) == 0 }
    }

    fn without_echo(self) -> Self {
        let mut silent = self.0;
        silent.c_lflag &= !libc::ECHO;
        TerminalMode(silent)
    }
}

pub struct EchoGuard(Option<TerminalMode>);

impl EchoGuard {
    pub fn disable() -> Self {
        EchoGuard(TerminalMode::capture().filter(|saved| saved.without_echo().restore()))
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if let Some(saved) = &self.0 {
            saved.restore();
        }
    }
}
