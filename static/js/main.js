/* 벚꽃 생성 */
document.addEventListener("DOMContentLoaded", () => {
    const container = document.querySelector(".sakura-container");
    if (!container) return;

    const colors = ["#ff9bcf", "#ffc8e6"];

    function createPetal() {
        const petal = document.createElement("div");
        petal.classList.add("petal");

        // 랜덤 위치
        petal.style.left = Math.random() * 100 + "vw";

        // 색상 랜덤
        petal.style.background = colors[Math.floor(Math.random() * colors.length)];

        // 애니메이션 속도 랜덤
        const fallTime = 5 + Math.random() * 4;
        const swayTime = 3 + Math.random() * 3;

        petal.style.animation = `
            fall ${fallTime}s linear infinite,
            sway ${swayTime}s ease-in-out infinite alternate
        `;

        container.appendChild(petal);

        // 제거
        setTimeout(() => {
            petal.remove();
        }, fallTime * 1000 + 1000);
    }

    setInterval(createPetal, 260);
});

/* 인덱스 전용: 타이틀 스크롤 & 소개 등장 */
const titleWrapper = document.getElementById("titleWrapper");
if (titleWrapper) {
    window.addEventListener("scroll", () => {
        if (window.scrollY > 150) {
            titleWrapper.style.transform = "translate(-50%, -150%)";
            titleWrapper.style.opacity = "0";
        } else {
            titleWrapper.style.transform = "translate(-50%, -50%)";
            titleWrapper.style.opacity = "1";
        }
    });
}

const photos = document.querySelectorAll(".photo");
const texts = document.querySelectorAll(".chapter-text");

if (photos.length || texts.length) {
    window.addEventListener("scroll", () => {
        const trigger = window.innerHeight * 0.8;
        photos.forEach((p) => {
            const top = p.getBoundingClientRect().top;
            if (top < trigger) p.classList.add("show");
        });
        texts.forEach((t) => {
            const top = t.getBoundingClientRect().top;
            if (top < trigger) t.classList.add("show");
        });
    });
}
