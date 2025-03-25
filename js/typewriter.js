document.addEventListener("DOMContentLoaded", () => {
	const typewriterEl = document.getElementById("typewriter");
	if (!typewriterEl) return;

	const text = [
	  "Hi, I am Simone,",
	  "I'm a Cybersecurity student,",
	  "currently working as a pentester."
	];

	const speed = 60; // velocità scrittura (ms per carattere)
	let line = 0;
	let charIndex = 0;

	function typeWriter() {
	  if (line < text.length) {
		if (charIndex < text[line].length) {
		  typewriterEl.innerHTML += text[line].charAt(charIndex);
		  charIndex++;
		  setTimeout(typeWriter, speed);
		} else {
		  typewriterEl.innerHTML += "<br>";
		  charIndex = 0;
		  line++;
		  setTimeout(typeWriter, speed + 200);
		}
	  }
	}

	typeWriter();
  });
