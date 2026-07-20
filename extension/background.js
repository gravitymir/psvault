// The extension has no popup: clicking the toolbar icon opens the full UI in a
// tab. A dedicated tab gives the vault room to breathe (a popup is capped at
// ~800x600). Kept permission-free on purpose — querying existing tabs by URL
// would require the "tabs" permission, which we deliberately avoid.
chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: chrome.runtime.getURL("index.html") });
});
