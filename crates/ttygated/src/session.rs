#[cfg(test)]
mod tests {
    #[test]
    fn dependency_surface_compiles() {
        let _ = pty_process::Size::new(24, 80);
        let _ = nix::sys::signal::Signal::SIGHUP;
        let _ = tokio::process::Command::new("/bin/true");
        let (_sender, _receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let _ = tokio::time::Duration::from_secs(1);
    }
}
