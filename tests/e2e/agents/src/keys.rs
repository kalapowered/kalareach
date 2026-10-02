//! The variables that would give an agent a model account other than the person's login: a
//! provider's key, token or base address, a cloud account's credentials, and the variables an agent
//! reads to move its data or its configuration.
//!
//! A part with a login runs the agent on the login its build list names, so no session may export
//! one of these but the one variable the build list gives it. Three things hold that by
//! construction. The harness runs the driver with a cleared environment, so the person's shell
//! passes it nothing. The environment a session is created with is built from the host's own
//! variables and the build list's, and [`strip`] takes every name the entry clears out of it again,
//! whatever put it there. And the session's shell writes the names it exports before each prompt,
//! which `provenance` checks against the same list before the agent is started.
//!
//! A pattern is a name, a prefix that ends in `*`, or a suffix that begins with `*`. Names that
//! begin with [`PRODUCT`] are the product's own and no pattern clears them.

use std::io::Read;

/// What the names of the product's own variables begin with.
pub const PRODUCT: &str = "KR_";

/// Whether `pattern` names `name`: the name itself, or every name that begins with the text before
/// a closing `*`, or ends with the text after an opening `*`. A name of the product's own is never
/// named by a pattern.
#[must_use]
pub fn names(pattern: &str, name: &str) -> bool {
    if name.starts_with(PRODUCT) {
        return false;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else {
        pattern == name
    }
}

/// Whether any of `patterns` names `name`.
#[must_use]
pub fn cleared(patterns: &[String], name: &str) -> bool {
    patterns.iter().any(|pattern| names(pattern, name))
}

/// Takes out of `variables` every name `patterns` clear but for the names in `allowed`, which the
/// build list sets itself, and returns the names it took out, never a value.
pub fn strip(
    variables: &mut Vec<(String, String)>,
    patterns: &[String],
    allowed: &[String],
) -> Vec<String> {
    let mut taken = Vec::new();
    variables.retain(|(name, _)| {
        let clear = cleared(patterns, name) && !allowed.contains(name);
        if clear {
            taken.push(name.clone());
        }
        !clear
    });
    taken
}

/// The variable naming the file descriptor the harness passes the values of the other keys its own
/// shell holds on: a pipe, one value on each line, so a part can search the run's directory for them
/// and no session is given any.
pub const SCAN_DESCRIPTOR_VARIABLE: &str = "KR_AGENTS_SCAN_FD";

/// The shortest value that is searched for: a shorter one is not a key and would match ordinary
/// text.
pub const SHORTEST: usize = crate::confine::SECRET_LENGTH;

/// Reads the values [`SCAN_DESCRIPTOR_VARIABLE`] names a descriptor for, one on each line, to its
/// end. The pipe is empty afterwards. A value shorter than [`SHORTEST`] is not returned.
///
/// # Errors
///
/// Returns why the descriptor could not be read: none is named, or it is not one.
pub fn scan_values_from_descriptor() -> Result<Vec<String>, String> {
    let named = std::env::var(SCAN_DESCRIPTOR_VARIABLE)
        .map_err(|_| format!("{SCAN_DESCRIPTOR_VARIABLE} names no descriptor"))?;
    let descriptor: u32 = named
        .parse()
        .map_err(|_| format!("{SCAN_DESCRIPTOR_VARIABLE} is not a descriptor"))?;
    let mut text = String::new();
    std::fs::File::open(format!("/dev/fd/{descriptor}"))
        .and_then(|mut file| file.read_to_string(&mut text))
        .map_err(|error| format!("descriptor {descriptor}: {error}"))?;
    Ok(searchable_values(&text))
}

/// The lines of `text` that are long enough to be a key: at least [`SHORTEST`] characters. Every one
/// is searched for in the run's directory; a result is held out of only those that
/// [`crate::confine::searchable`] accepts, since the others cannot be told from the result's own
/// syntax, and the harness searches the evidence for all of them.
#[must_use]
pub fn searchable_values(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| line.chars().count() >= SHORTEST)
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(patterns: &[&str]) -> Vec<String> {
        patterns
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect()
    }

    /// The patterns every entry of the build list carries, which the plugins repository's own test
    /// holds each entry to.
    fn every_entry() -> Vec<String> {
        list(&[
            "OPENAI_*",
            "ANTHROPIC_*",
            "CLAUDE_CODE_*",
            "CODEX_*",
            "GEMINI_*",
            "GOOGLE_*",
            "VERTEX_*",
            "GCLOUD_*",
            "CLOUDSDK_*",
            "CLOUD_ML_*",
            "CODE_ASSIST_*",
            "MOONSHOT_*",
            "KIMI_*",
            "OPENROUTER_*",
            "OPENCODE_*",
            "AWS_*",
            "AZURE_*",
            "CLOUDFLARE_*",
            "*_KEY",
            "*_PAT",
            "*_APIKEY",
            "DATABRICKS_*",
            "INFOMANIAK_*",
            "PRIVATEMODE_*",
            "SNOWFLAKE_*",
            "WATSONX_*",
            "*_ENDPOINT",
            "*_API_KEY",
            "*_API_TOKEN",
            "*_ACCESS_TOKEN",
            "*_AUTH_TOKEN",
            "*_TOKEN",
            "*_SECRET",
            "*_SECRET_KEY",
            "*_ACCESS_KEY",
            "*_PASSWORD",
            "*_BASE_URL",
            "*_API_BASE",
        ])
    }

    /// A pattern is a name, a prefix or a suffix, and a product name is never one a pattern names.
    #[test]
    fn a_pattern_is_a_name_a_prefix_or_a_suffix_and_the_products_names_are_none() {
        assert!(names("OPENAI_*", "OPENAI_API_KEY"));
        assert!(names("*_API_KEY", "GROQ_API_KEY"));
        assert!(names("AWS_PROFILE", "AWS_PROFILE"));
        assert!(!names("AWS_PROFILE", "AWS_PROFILE_2"));
        assert!(!names("OPENAI_*", "XOPENAI_API_KEY"));
        assert!(!names("*_API_KEY", "GROQ_API_KEY_FILE"));
        // The product's own names are never cleared, whatever they end with.
        for own in [
            "KR_SESSION_TOKEN",
            "KR_SHELL_BRIDGE_SECRET",
            "KR_WORKER_ENDPOINT",
        ] {
            assert!(!cleared(&every_entry(), own), "{own}");
        }
    }

    /// Every variable each approved agent documents for a model account, a provider or a moved
    /// home is cleared, and what a session ordinarily exports is not.
    #[test]
    fn every_documented_provider_variable_is_cleared_and_an_ordinary_one_is_not() {
        let patterns = every_entry();
        let documented = [
            // Claude Code.
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_MODEL",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_USE_BEDROCK",
            "AWS_BEARER_TOKEN_BEDROCK",
            "CLOUD_ML_REGION",
            // Codex.
            "OPENAI_API_KEY",
            "OPENAI_BASE_URL",
            "OPENAI_ORG_ID",
            "CODEX_API_KEY",
            "CODEX_HOME",
            // Kimi Code.
            "KIMI_API_KEY",
            "KIMI_BASE_URL",
            "KIMI_CODE_HOME",
            "MOONSHOT_API_KEY",
            "MOONSHOT_BASE_URL",
            // Gemini CLI.
            "GEMINI_API_KEY",
            "GEMINI_CLI_HOME",
            "GOOGLE_API_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_CLOUD_PROJECT",
            "GOOGLE_GENAI_USE_VERTEXAI",
            "GOOGLE_GEMINI_BASE_URL",
            "CLOUDSDK_CONFIG",
            "CODE_ASSIST_ENDPOINT",
            // OpenCode, which reads a provider's key from the variable that provider names.
            "OPENROUTER_API_KEY",
            "OPENCODE_CONFIG",
            "OPENCODE_CONFIG_CONTENT",
            "OPENCODE_SERVER_PASSWORD",
            "GROQ_API_KEY",
            "CEREBRAS_API_KEY",
            "MISTRAL_API_KEY",
            "XAI_API_KEY",
            "GITHUB_TOKEN",
            "HF_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AZURE_RESOURCE_NAME",
            "CLOUDFLARE_API_TOKEN",
            "SOME_PROVIDER_BASE_URL",
            // Names from the catalogue of the pinned OpenCode that the first lists missed.
            "WATSONX_AI_APIKEY",
            "CLARIFAI_PAT",
            "AICORE_SERVICE_KEY",
            "SNOWFLAKE_CORTEX_PAT",
            "DATABRICKS_HOST",
            "WATSONX_AI_PROJECT_ID",
            "PRIVATEMODE_ENDPOINT",
            "AWS_BEARER_TOKEN_BEDROCK",
        ];
        for name in documented {
            assert!(cleared(&patterns, name), "{name} is cleared");
        }
        // OpenCode keeps its data and configuration where these variables say, so its entry clears them too.
        let opencode = [patterns.clone(), list(&["XDG_*"])].concat();
        for name in [
            "XDG_DATA_HOME",
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
        ] {
            assert!(cleared(&opencode, name), "{name} is cleared for OpenCode");
        }
        let ordinary = [
            "PATH",
            "HOME",
            "TERM",
            "TMPDIR",
            "ZDOTDIR",
            "SHELL",
            "LANG",
            "USER",
            "LOGNAME",
            "PWD",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "SSH_AUTH_SOCK",
            "HARMLESS_CONTROL",
            "KR_RUNTIME_DIR",
            "KR_SESSION_TOKEN",
        ];
        for name in ordinary {
            assert!(!cleared(&patterns, name), "{name} is not cleared");
        }
    }

    /// Stripping takes out every cleared name and nothing else, keeps the names the build list
    /// sets itself, and returns names alone.
    #[test]
    fn stripping_takes_out_every_cleared_name_and_keeps_the_rest() {
        let mut variables: Vec<(String, String)> = [
            ("PATH", "/usr/bin"),
            ("OPENAI_API_KEY", "value-one"),
            ("GEMINI_API_KEY", "value-two"),
            ("GEMINI_CLI_TRUST_WORKSPACE", "true"),
            ("GROQ_API_KEY", "value-three"),
            ("HARMLESS_CONTROL", "1"),
            ("KR_SESSION_TOKEN", "product"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
        let allowed = list(&["GEMINI_API_KEY", "GEMINI_CLI_TRUST_WORKSPACE"]);
        let taken = strip(&mut variables, &every_entry(), &allowed);
        assert_eq!(taken, ["OPENAI_API_KEY", "GROQ_API_KEY"]);
        let kept: Vec<&str> = variables.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            kept,
            [
                "PATH",
                "GEMINI_API_KEY",
                "GEMINI_CLI_TRUST_WORKSPACE",
                "HARMLESS_CONTROL",
                "KR_SESSION_TOKEN"
            ]
        );
        assert!(taken.iter().all(|name| !name.contains("value")));
    }

    /// Values to search for are the lines that are long enough.
    #[test]
    fn every_long_value_is_searched_for_in_the_runs_directory() {
        let text = "short\nabcdefghijklmnop\nhas\"quote-and-more-text\r\nhas space but long enough\n\nabcdefghijklmnopq\n";
        assert_eq!(
            searchable_values(text),
            [
                "abcdefghijklmnop",
                "has\"quote-and-more-text",
                "has space but long enough",
                "abcdefghijklmnopq"
            ]
        );
    }
}
