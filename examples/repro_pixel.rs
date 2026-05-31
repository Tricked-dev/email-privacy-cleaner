use email_privacy_cleaner::{clean_html, CleanerConfig};

fn main() {
    let mut cfg = CleanerConfig::default();
    cfg.finalize();

    let cases: &[(&str, &str)] = &[
        (
            "no dims, empty alt",
            r#"<img src="https://tracker.unknown.example/p.gif" alt="">"#,
        ),
        (
            "no dims, no alt",
            r#"<img src="https://tracker.unknown.example/p.gif">"#,
        ),
        (
            "no dims, with alt",
            r#"<img src="https://tracker.unknown.example/p.gif" alt="open">"#,
        ),
        (
            "1x1 unknown host empty alt",
            r#"<img src="https://static.unknown.example/spacer.gif" width="1" height="1" alt="">"#,
        ),
        (
            "srcset only beacon",
            r#"<img srcset="https://tracker.unknown.example/p.gif 1x" width="1" height="1" alt="">"#,
        ),
        (
            "layout spacer 10x1",
            r#"<img src="https://static.unknown.example/spacer.gif" width="10" height="1" alt="">"#,
        ),
        (
            "paren in style url",
            r#"<div style="background-image:url(https://doubleclick.net/p(1).gif)"></div>"#,
        ),
        (
            "css url quoted",
            r#"<div style="background-image:url('https://doubleclick.net/p.gif')"></div>"#,
        ),
        (
            "css url with spaces",
            r#"<div style="background-image:url(  https://doubleclick.net/p.gif  )"></div>"#,
        ),
    ];
    for (label, html) in cases {
        let r = clean_html(html, None, &cfg).unwrap();
        println!("[{label}]");
        println!("  in : {html}");
        println!("  out: {}", r.html);
        println!("  pixels_removed={}\n", r.pixels_removed);
    }
}
