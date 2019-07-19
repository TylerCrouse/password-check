//! # Password check
//! `password-check` is a utility to check a password against the list maintained by
//! [Have I been Pwned](https://haveibeenpwned.com).
//!
//! The passwords API is free and not rate limited.
//!
//! You can read more about the specific api [here](https://haveibeenpwned.com/API/v3#PwnedPasswords).
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use regex::Regex;

/// Returns the number of times a given password has been "pwned".
///
/// The password is hashed and then the first 5 characters are used to lookup possible matches. The returned
/// list is then scanned for an exact match. A users full password is never sent to the third party API.
///
/// 0 is returned when the password does not appear in the list as "pwned".
///
/// # Arguments
/// * `password` - A string that holds the password to checked.
/// * `user_agent` - A string that holds the user-agent to send. This should be something unique
/// and identifiable for your application.
///
/// # Errors
/// Will return an error if the http request fails.
///
/// # Examples
/// ```
/// let password = "password";
/// let user_agent = "your-user-agent-string";
/// let pwned_count = password_check::get_pwned_count(password, user_agent).unwrap();
/// assert_eq!(pwned_count, 3730471);
/// ```
///
pub fn get_pwned_count(password: &str, user_agent: &str) -> Result<i32, reqwest::Error> {
    let sha1 = get_sha1(password);

    let client = reqwest::Client::new();
    let body_text = client.get(build_request_url(sha1.as_str()).as_str())
        .header("User-Agent", user_agent)
        .send()?
        .text()?;

    let regex = Regex::new(format!(r"{}:(?P<num>\d+)", sha1[5..].to_string().to_uppercase())
        .as_str())
        .unwrap();
    for cap in regex.captures_iter(body_text.as_str()) {
        if cap.len() == 2 {
            // TODO: better fallback than returning 0 if the parse fails
            return Ok(*&cap[1].parse::<i32>().unwrap_or(0));
        }
    }

    Ok(0)
}

fn get_sha1(input_str: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.input_str(input_str);

    hasher.result_str()
}

fn build_request_url(sha1: &str) -> String {
    format!("https://api.pwnedpasswords.com/range/{}", sha1[..5].to_string())
}


#[cfg(test)]
mod tests {
    use crate::password_check::{build_request_url, get_pwned_count, get_sha1};

    #[test]
    fn test_sha1() {
        let result = get_sha1("test");
        assert_eq!("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", result);

        let result1 = get_sha1("test_again_with_more_chars");
        assert_eq!("9322163d15c12e08ca0a2b59d30c48dc9688a845", result1);
    }

    #[test]
    fn test_get_url() {
        let result = build_request_url(get_sha1("test").as_str());
        assert_eq!("https://api.pwnedpasswords.com/range/a94a8", result);

        let result1 = build_request_url(get_sha1("test_again_with_more_chars")
            .as_str());
        assert_eq!("https://api.pwnedpasswords.com/range/93221", result1);
    }

    #[test]
    fn test_pwned_count() {
        let pwned_count = get_pwned_count("password", "rust-pwd-check-test")
            .unwrap();
        assert_eq!(pwned_count, 3730471);

        let pwned_count1 = get_pwned_count("betterpass", "rust-pwd-check-test")
            .unwrap();
        assert_eq!(pwned_count1, 2);

        let pwned_count3
            = get_pwned_count("@#$@#$#2thispassword123wontbe123inthere123123hopefully123%$%#@",
                              "rust-pwd-check-test").unwrap();
        assert_eq!(pwned_count3, 0);
    }
}




