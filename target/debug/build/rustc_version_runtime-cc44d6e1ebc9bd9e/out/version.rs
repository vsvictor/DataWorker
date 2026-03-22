
            /// Returns the `rustc` SemVer version and additional metadata
            /// like the git short hash and build date.
            pub fn version_meta() -> VersionMeta {
                VersionMeta {
                    semver: Version {
                        major: 1,
                        minor: 94,
                        patch: 0,
                        pre: vec![],
                        build: vec![],
                    },
                    host: "x86_64-unknown-linux-gnu".to_owned(),
                    short_version_string: "rustc 1.94.0 (4a4ef493e 2026-03-02)".to_owned(),
                    commit_hash: Some("4a4ef493e3a1488c6e321570238084b38948f6db".to_owned()),
                    commit_date: Some("2026-03-02".to_owned()),
                    build_date: None,
                    channel: Channel::Stable,
                }
            }
            