// 벚꽃 생성
const sakuraContainer = document.getElementById("sakuraContainer");
if (sakuraContainer) {
    const colors = ["#ff9bcf", "#ffc8e6"];
    function createPetal() {
        const petal = document.createElement("div");
        petal.classList.add("petal");
        petal.style.left = Math.random() * 100 + "vw";
        petal.style.background = colors[Math.floor(Math.random() * colors.length)];
        petal.style.animationDuration = 6 + Math.random() * 4 + "s";
        sakuraContainer.appendChild(petal);
        setTimeout(() => petal.remove(), 11000);
    }
    setInterval(createPetal, 260);
}

// 타이틀 스크롤 시 위로 사라지기
const titleWrapper = document.getElementById("titleWrapper");
window.addEventListener("scroll", () => {
    if (!titleWrapper) return;
    if (window.scrollY > 150) {
        titleWrapper.style.transform = "translate(-50%, -150%)";
        titleWrapper.style.opacity = "0";
    } else {
        titleWrapper.style.transform = "translate(-50%, -50%)";
        titleWrapper.style.opacity = "1";
    }
});

// 스크롤 시 소개 사진 + 소개글 등장
window.addEventListener("scroll", () => {
    const photos = document.querySelectorAll(".photo");
    const texts = document.querySelectorAll(".chapter-text");
    const trigger = window.innerHeight * 0.8;

    photos.forEach(p => {
        const rect = p.getBoundingClientRect();
        if (rect.top < trigger) p.classList.add("show");
    });
    texts.forEach(t => {
        const rect = t.getBoundingClientRect();
        if (rect.top < trigger) t.classList.add("show");
    });
});
