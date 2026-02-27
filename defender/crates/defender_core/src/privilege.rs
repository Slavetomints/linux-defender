use nix::unistd::Uid;

pub fn require_root() -> Result<(), String> {
    if !Uid::effective().is_root() {
        return Err("[X] This module requires root privileges".into());
    }

    Ok(())
}
