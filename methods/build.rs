use std::env;

fn main() {
    let guest_code = env::var("GUEST_CODE")
        .expect("ERROR: Make sure to define GUEST_CODE env var pointing to the code to be proved");

    let _ = std::fs::remove_file("guest");

    let failed_link_msg = "Failed to create symlink to guest code";

    #[cfg(unix)]
    std::os::unix::fs::symlink(guest_code, "guest").expect(failed_link_msg);

    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(guest_code, "guest").expect(failed_link_msg);

    risc0_build::embed_methods();
}
