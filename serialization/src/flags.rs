static mut default_flags: u32 = 0;

pub fn set_default_flags(flags: u32) {
	unsafe {
		default_flags = flags
	}
}

pub fn get_default_flags() -> u32 {
	unsafe {
		default_flags
	}
}
