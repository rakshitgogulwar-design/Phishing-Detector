import React, { useRef, useEffect } from 'react';
import './LetterGlitch.css';

export const LetterGlitch = ({
  glitchColors = ['#2b4539', '#61dca3', '#61bdfa', '#a855f7', '#06b6d4'],
  glitchSpeed = 50,
  centerVignette = true,
  outerVignette = false,
  smooth = true,
  letters = '0123456789ABCDEF!@#$%^&*()_+-=[]{}|;:,.<>?/',
  className = ''
}) => {
  const canvasRef = useRef(null);
  const animationRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = (canvas.width = canvas.offsetWidth || window.innerWidth);
    let height = (canvas.height = canvas.offsetHeight || window.innerHeight);

    const fontSize = 16;
    const columns = Math.floor(width / fontSize);
    const rows = Math.floor(height / fontSize);
    const charArray = letters.split('');

    // Grid matrix representation
    const grid = [];
    for (let r = 0; r < rows; r++) {
      const row = [];
      for (let c = 0; c < columns; c++) {
        row.push({
          char: charArray[Math.floor(Math.random() * charArray.length)],
          color: glitchColors[Math.floor(Math.random() * glitchColors.length)],
          targetOpacity: Math.random() * 0.8 + 0.2,
          currentOpacity: Math.random()
        });
      }
      grid.push(row);
    }

    let lastTime = 0;

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = canvas.offsetWidth || window.innerWidth;
      height = canvas.height = canvas.offsetHeight || window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const render = (time) => {
      if (time - lastTime > glitchSpeed) {
        lastTime = time;

        // Randomly glitch grid characters
        const glitchCount = Math.floor((columns * rows) * 0.08);
        for (let i = 0; i < glitchCount; i++) {
          const r = Math.floor(Math.random() * rows);
          const c = Math.floor(Math.random() * columns);
          if (grid[r] && grid[r][c]) {
            grid[r][c].char = charArray[Math.floor(Math.random() * charArray.length)];
            grid[r][c].color = glitchColors[Math.floor(Math.random() * glitchColors.length)];
            grid[r][c].targetOpacity = Math.random() * 0.85 + 0.15;
          }
        }
      }

      ctx.fillStyle = '#070b14';
      ctx.fillRect(0, 0, width, height);
      ctx.font = `${fontSize}px "JetBrains Mono", monospace`;

      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < columns; c++) {
          const cell = grid[r][c];
          if (!cell) continue;

          if (smooth) {
            cell.currentOpacity += (cell.targetOpacity - cell.currentOpacity) * 0.1;
          } else {
            cell.currentOpacity = cell.targetOpacity;
          }

          ctx.fillStyle = cell.color;
          ctx.globalAlpha = cell.currentOpacity;
          ctx.fillText(cell.char, c * fontSize, (r + 1) * fontSize);
        }
      }
      ctx.globalAlpha = 1.0;

      // Center vignette gradient
      if (centerVignette) {
        const centerGrad = ctx.createRadialGradient(
          width / 2, height / 2, 0,
          width / 2, height / 2, Math.max(width, height) * 0.6
        );
        centerGrad.addColorStop(0, 'rgba(7, 11, 20, 0.85)');
        centerGrad.addColorStop(0.5, 'rgba(7, 11, 20, 0.4)');
        centerGrad.addColorStop(1, 'transparent');
        ctx.fillStyle = centerGrad;
        ctx.fillRect(0, 0, width, height);
      }

      // Outer vignette gradient
      if (outerVignette) {
        const outerGrad = ctx.createRadialGradient(
          width / 2, height / 2, Math.max(width, height) * 0.3,
          width / 2, height / 2, Math.max(width, height) * 0.7
        );
        outerGrad.addColorStop(0, 'transparent');
        outerGrad.addColorStop(1, 'rgba(7, 11, 20, 0.95)');
        ctx.fillStyle = outerGrad;
        ctx.fillRect(0, 0, width, height);
      }

      animationRef.current = requestAnimationFrame(render);
    };

    animationRef.current = requestAnimationFrame(render);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, [glitchColors, glitchSpeed, centerVignette, outerVignette, smooth, letters]);

  return (
    <div className={`letterglitch-container ${className}`} style={{ width: '100%', height: '100%', position: 'relative', overflow: 'hidden' }}>
      <canvas ref={canvasRef} className="letterglitch-canvas" style={{ width: '100%', height: '100%', display: 'block' }} />
    </div>
  );
};

export default LetterGlitch;
