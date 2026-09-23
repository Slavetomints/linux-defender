//! Covers `src/anti_persistence/php_shells.rs`.

use std::fs;

use defender_cli::anti_persistence::php_shells;
use tempfile::TempDir;

use crate::common::write_file;

const WEBSHELL: &str = r#"<?php system($_GET['cmd']); eval($payload); ?>"#;
const CLEAN: &str = r#"<?php echo "hello world"; ?>"#;

#[test]
fn flags_a_webshell_and_names_the_keywords() {
    let root = TempDir::new().unwrap();
    write_file(root.path(), "shell.php", WEBSHELL);

    let found = php_shells::find_shells(root.path());

    assert_eq!(found.len(), 1);
    assert!(found[0].location.ends_with("shell.php"));
    assert!(found[0].keywords.contains(&"system".to_string()));
    assert!(found[0].keywords.contains(&"eval".to_string()));
    assert_eq!(found[0].score, found[0].keywords.len() as u16);
}

#[test]
fn ignores_clean_files() {
    let root = TempDir::new().unwrap();
    write_file(root.path(), "index.php", CLEAN);
    write_file(root.path(), "style.css", "body { color: red; }");

    assert!(php_shells::find_shells(root.path()).is_empty());
}

#[test]
fn scans_nested_directories() {
    let root = TempDir::new().unwrap();
    write_file(root.path(), "a/b/c/hidden.php", WEBSHELL);

    let found = php_shells::find_shells(root.path());

    assert_eq!(found.len(), 1);
    assert!(found[0].location.ends_with("hidden.php"));
}

#[test]
fn skips_unreadable_and_binary_files() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("image.bin"), [0xFF, 0xFE, 0x00, 0x01]).unwrap();
    write_file(root.path(), "shell.php", WEBSHELL);

    // Non-UTF-8 content must be skipped rather than panicking.
    let found = php_shells::find_shells(root.path());

    assert_eq!(found.len(), 1);
    assert!(found[0].location.ends_with("shell.php"));
}

#[test]
fn an_empty_tree_yields_nothing() {
    let root = TempDir::new().unwrap();
    assert!(php_shells::find_shells(root.path()).is_empty());
}

#[test]
fn a_missing_root_yields_nothing_rather_than_erroring() {
    let root = TempDir::new().unwrap();
    let missing = root.path().join("does-not-exist");

    assert!(php_shells::find_shells(&missing).is_empty());
}

#[test]
fn ranks_a_dense_shell_above_a_single_hit() {
    let root = TempDir::new().unwrap();
    write_file(root.path(), "one.php", "<?php eval($x); ?>");
    write_file(
        root.path(),
        "many.php",
        "<?php system($a); exec($b); popen($c); eval($d); ?>",
    );

    let found = php_shells::find_shells(root.path());
    assert_eq!(found.len(), 2);

    let many = found
        .iter()
        .find(|f| f.location.ends_with("many.php"))
        .unwrap();
    let one = found
        .iter()
        .find(|f| f.location.ends_with("one.php"))
        .unwrap();

    assert!(many.score > one.score);
    assert_eq!(one.score, 1);
}
