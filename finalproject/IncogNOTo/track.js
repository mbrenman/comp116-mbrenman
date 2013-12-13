// Run on every page that matches: "http://*/*" and "https://*/* when loaded

hostname = window.location.host

chrome.storage.sync.get(null, function (items) {

	count = items[hostname];
	if (!count){count = 0}
	count += 1;

	//Create a new object to hold the count value
	var obj = {};
	obj[hostname] = count;

	chrome.storage.sync.set(obj);
});
