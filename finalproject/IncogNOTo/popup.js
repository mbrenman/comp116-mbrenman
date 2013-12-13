var historyTrackerWindow = {

  showHistory: function (e) {
    chrome.storage.sync.get(null, function (items) {
      for (var key in items){
        var li = document.createElement('li');
        var text = key + " : " + items[key]
        var textNode = document.createTextNode(text);
        li.appendChild(textNode);
        document.getElementById("myList").appendChild(li);       
      }
    });
  },
};

// Run the history display script as soon as the document's DOM is ready.
document.addEventListener('DOMContentLoaded', function () {
  historyTrackerWindow.showHistory();
});