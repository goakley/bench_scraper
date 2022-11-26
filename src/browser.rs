#![warn(missing_docs)]
use strum_macros::EnumIter;

#[derive(Debug, PartialEq, Eq, EnumIter)]
#[non_exhaustive]
/// A web browser engine that handles the core functionality of a web browser.
pub enum KnownEngine {
    /// The Firefox web engine, powering Firefox.
    Firefox,
    /// The Chromium web engine, powering Chromium, Chrome, and various other derivatives.
    Chromium(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq, EnumIter)]
#[non_exhaustive]
/// A browser from which cookies can be pulled.
pub enum KnownBrowser {
    /// The [`Firefox`] web browser from Mozilla.
    ///
    /// [`Firefox`]: https://www.mozilla.org/firefox/
    Firefox,
    /// The [`Chrome`] web browser from Google.
    ///
    /// [`Chrome`]: https://www.google.com/chrome/
    Chrome,
    /// The [`Beta`] release of the Chrome web browser from Google.
    ///
    /// [`Beta`]: https://www.google.com/chrome/beta/
    ChromeBeta,
    /// The [`Chromium`] open-source web browser maintained by Google.
    ///
    /// [`Chromium`]: https://www.chromium.org/chromium-projects/
    Chromium,
    /// [`Microsoft Edge`], the Windows 10/11 default browser.
    ///
    /// [`Microsoft Edge`]: https://www.microsoft.com/edge/
    #[cfg(target_os = "windows")]
    Edge,
}

impl KnownBrowser {
    /// Gets the engine used to power the web browser.
    pub fn engine(&self) -> KnownEngine {
        match self {
            KnownBrowser::Firefox => KnownEngine::Firefox,
            #[cfg(target_os = "linux")]
            KnownBrowser::Chrome => KnownEngine::Chromium("Chrome Safe Storage"),
            #[cfg(target_os = "macos")]
            KnownBrowser::Chrome => KnownEngine::Chromium("Chrome"),
            #[cfg(target_os = "windows")]
            KnownBrowser::Chrome => KnownEngine::Chromium(""),
            #[cfg(target_os = "linux")]
            KnownBrowser::ChromeBeta => KnownEngine::Chromium("Chrome Safe Storage"),
            #[cfg(target_os = "macos")]
            KnownBrowser::ChromeBeta => KnownEngine::Chromium("Chrome"),
            #[cfg(target_os = "windows")]
            KnownBrowser::ChromeBeta => KnownEngine::Chromium(""),
            #[cfg(target_os = "linux")]
            KnownBrowser::Chromium => KnownEngine::Chromium("Chromium Safe Storage"),
            #[cfg(target_os = "macos")]
            KnownBrowser::Chromium => KnownEngine::Chromium("Chromium"),
            #[cfg(target_os = "windows")]
            KnownBrowser::Chromium => KnownEngine::Chromium(""),
            #[cfg(target_os = "windows")]
            KnownBrowser::Edge => KnownEngine::Chromium(""),
        }
    }

    /// Gets the default user configuration path for the web browser.
    ///
    /// While most browsers have a default configuration path, there is no guarantee that the environment in which this function runs has enough context to determine what that path is.
    /// The function returns [`None`] in that case.
    pub fn default_config_path(&self) -> Option<std::path::PathBuf> {
        match self {
            #[cfg(target_os = "linux")]
            KnownBrowser::Firefox => dirs::home_dir().map(|p| p.join(".mozilla").join("firefox")),
            #[cfg(target_os = "macos")]
            KnownBrowser::Firefox => dirs::data_dir().map(|p| p.join("Firefox")),
            #[cfg(target_os = "windows")]
            KnownBrowser::Firefox => {
                dirs::data_dir().map(|p| p.join("Mozilla").join("Firefox").join("Profiles"))
            }
            #[cfg(target_os = "linux")]
            KnownBrowser::Chrome => {
                dirs::home_dir().map(|p| p.join(".config").join("google-chrome"))
            }
            #[cfg(target_os = "macos")]
            KnownBrowser::Chrome => dirs::data_dir().map(|p| p.join("Google").join("Chrome")),
            #[cfg(target_os = "windows")]
            KnownBrowser::Chrome => {
                dirs::data_local_dir().map(|p| p.join("Google").join("Chrome").join("User Data"))
            }
            #[cfg(target_os = "linux")]
            KnownBrowser::ChromeBeta => {
                dirs::home_dir().map(|p| p.join(".config").join("google-chrome-beta"))
            }
            #[cfg(target_os = "macos")]
            KnownBrowser::ChromeBeta => {
                dirs::data_dir().map(|p| p.join("Google").join("Chrome Beta"))
            }
            #[cfg(target_os = "windows")]
            KnownBrowser::ChromeBeta => dirs::data_local_dir()
                .map(|p| p.join("Google").join("Chrome Beta").join("User Data")),
            #[cfg(target_os = "linux")]
            KnownBrowser::Chromium => dirs::home_dir().map(|p| p.join(".config").join("chromium")),
            #[cfg(target_os = "macos")]
            KnownBrowser::Chromium => dirs::data_dir().map(|p| p.join("Chromium")),
            #[cfg(target_os = "windows")]
            KnownBrowser::Chromium => {
                dirs::data_local_dir().map(|p| p.join("Chromium").join("User Data"))
            }
            #[cfg(target_os = "windows")]
            KnownBrowser::Edge => {
                dirs::data_local_dir().map(|p| p.join("Microsoft").join("Edge").join("User Data"))
            }
        }
    }
}
