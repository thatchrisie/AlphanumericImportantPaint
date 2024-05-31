// Store the form IDs in an array
var formIds = [
  "whitelistForm",
  "blacklistForm",
  "deleteForm",
  "frejawhitelistForm",
  "frejablacklistForm",
  "frejadeleteForm",
]

// Attach event listeners for form submissions
formIds.forEach(function(formId) {
  document.getElementById(formId).addEventListener("submit", (event) => {
    handleSubmit(event, formId)
  });
});

function handleSubmit(event, formId) {
  // Prevent the default form submission behavior
  event.preventDefault();

  // Get the form data
  var form = document.getElementById(formId)
  
  var formData = new FormData(event.target);
  if (form.id.match("freja")) {
    formData.append("appType", "freja")
  } else {
    formData.append("appType", "swish")
  }

  // Perform a fetch request
  fetch(event.target.action, {
    method: 'POST',
    body: formData
  })
  .then(function(response) {
    if (response.ok) {
      // Response received successfully
      location.reload(); // Reload the page
    } else {
      // Error handling
      console.error("Error: " + response.status);
    }
  })
  .catch(function(error) {
    // Error handling
    console.error("Error: " + error.message);
  });
}


const getChildIndex = node => 
  Array.prototype.indexOf.call(node.parentNode.children, node);

// Keep track of the currently edited row
let editingRow = null;

function onTableRowHover(event) {
   const
    row = event.currentTarget,
    col = event.target,
    rowIndex = getChildIndex(row),
    colIndex = getChildIndex(col),
    allText = [...row.children].map(td => td.textContent);

  console.log(1)
  console.log(`Cell (${colIndex}, ${rowIndex}): ${event.target.textContent}`);
  console.log(`Row [${rowIndex}]: ${JSON.stringify(allText)}`);
}

let originalItem = ""; // Declare the variable outside the editRow function

function editRow(button) {
  if (editingRow) return;
  
  const row = button.parentNode.parentNode;
  const editButton = row.querySelector(".edit-button");
  const saveButton = row.querySelector(".save-button");
  const editInput = row.querySelector(".edit-input");
  const itemCell = row.querySelector(".item-cell"); // Item cell
  const valueCell = row.querySelector(".value-cell"); // Value cell

  // Store the original item and value data
  originalItem = itemCell.textContent; // Update the originalItem variable
  const originalValue = valueCell.textContent;

  // Show the edit input and hide the value text
  editInput.value = originalItem;
  editInput.style.display = "inline";
  valueCell.style.display = "none";

  // Toggle button visibility
  editButton.style.display = "none";
  saveButton.style.display = "inline";

  editingRow = row;
}


function saveRow(button, endpoint) {
   if (!editingRow) return;

  const row = editingRow;
  const editButton = row.querySelector(".edit-button");
  const saveButton = row.querySelector(".save-button");
  const editInput = row.querySelector(".edit-input");
  const itemCell = row.querySelector(".item-cell"); // Item cell
  const valueCell = row.querySelector(".value-cell"); // Value cell

  // Get the new item value
  const newItem = editInput.value;

  // Update the UI with the new item data

  if (newItem == "") {
    row.remove()
  }
  else {
    itemCell.textContent = newItem;
    editInput.style.display = "none";
    valueCell.style.display = "";
  
    // Toggle button visibility
    saveButton.style.display = "none";
    editButton.style.display = "inline";
  }

  // Send a POST request to the server
  const formData = new FormData();
  formData.append("formType", "editRow")
  formData.append("originalItem", originalItem);
  formData.append("newItem", newItem);

  if (row.className.match("swish")) {
    formData.append("appType", "swish")
  } else {
    formData.append("appType", "freja")
  }

  fetch(endpoint, {
    method: "POST",
    body: formData
  })
  .then(response => {
    if (!response.ok) {
      console.error("Error: " + response.status);
    }
  })
  .catch(error => {
    console.error("Error: " + error.message);
  });

  editingRow = null;
}

document.querySelectorAll('.swishHoverRow').forEach(function(tr) {
    // Now do something with my butto
  tr.onmouseover = function(event) {
    onTableRowHover(event)
  }
});
document.querySelectorAll('.edit-button').forEach(function(button) {
    // Now do something with my butto
  button.setAttribute("onclick", "javascript: editRow(this);" );
});

// ...
