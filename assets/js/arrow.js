window.scrollTo = selector => {
  document.querySelector(selector).scrollIntoView({
    behavior: 'smooth',
  })
}

document.addEventListener('alpine:init', () => {
  /* Calculates desired arrow opacity from scroll position */
  Alpine.magic('arrow', () => {
    const scrollPos = Math.min(window.scrollY / window.innerHeight, 1.0)
    return {
      opacity: 1.0 - (scrollPos / 0.8),
      bottom: 3.0 + (scrollPos * 3),
      hidden: scrollPos >= 0.8,
    }
  })
})

