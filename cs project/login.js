document.addEventListener('DOMContentLoaded', function () {
    // Selecting the Remember me checkbox
    const rememberMeCheckbox = document.getElementById('rememberMeCheckbox');
  
    // Adding event listener to the Remember me checkbox
    rememberMeCheckbox.addEventListener('change', function () {
      // Check if the checkbox is checked
      if (this.checked) {
        // Set localStorage to remember the user
        localStorage.setItem('rememberMe', 'true');
      } else {
        // Remove localStorage if the checkbox is unchecked
        localStorage.removeItem('rememberMe');
      }
    });
  
    // Checking if the Remember me checkbox was previously checked
    const rememberMe = localStorage.getItem('rememberMe');
    if (rememberMe === 'true') {
      rememberMeCheckbox.checked = true;
    }
  });
  