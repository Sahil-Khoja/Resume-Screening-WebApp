function toggleTheme() {
  const body = document.body;
  const isDark = body.classList.toggle("dark"); // toggle dark mode
  localStorage.setItem("theme", isDark ? "dark" : "light");

  // Update all toggle buttons
  document.querySelectorAll(".theme-toggle, .theme-switch").forEach(btn => {
    const icon = btn.querySelector("i");
    if (icon) {
      // remove both icons first
      icon.classList.remove("bi-moon-fill", "bi-sun-fill");
      // add the correct one
      icon.classList.add(isDark ? "bi-sun-fill" : "bi-moon-fill");
    } else {
      // login.html button uses text
      btn.textContent = isDark ? "☀️" : "🌙";
    }
  });
}

// On page load, set saved theme & icons
document.addEventListener("DOMContentLoaded", () => {
  const isDark = localStorage.getItem("theme") === "dark";
  if (isDark) {
    document.body.classList.add("dark");
  }

  // Set icons/text correctly
  document.querySelectorAll(".theme-toggle, .theme-switch").forEach(btn => {
    const icon = btn.querySelector("i");
    if (icon) {
      icon.classList.remove("bi-moon-fill", "bi-sun-fill");
      icon.classList.add(isDark ? "bi-sun-fill" : "bi-moon-fill");
    } else {
      btn.textContent = isDark ? "☀️" : "🌙";
    }
  });
});
