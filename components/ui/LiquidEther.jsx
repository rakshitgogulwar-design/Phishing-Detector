import React, { useRef, useEffect } from 'react';
import './LiquidEther.css';

export const LiquidEther = ({
  colors = ['#5227FF', '#FF9FFC', '#B497CF'],
  mouseForce = 20,
  cursorSize = 100,
  isViscous = false,
  viscous = 30,
  iterationsViscous = 32,
  iterationsPoisson = 32,
  resolution = 0.5,
  isBounce = false,
  autoDemo = true,
  autoSpeed = 0.5,
  autoIntensity = 2.2,
  takeoverDuration = 0.25,
  autoResumeDelay = 3000,
  autoRampDuration = 0.6,
  color0 = "#f0041c",
  color1 = "#cb1503",
  color2 = "#000000",
  className = ""
}) => {
  const canvasRef = useRef(null);
  const animFrameRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = (canvas.width = canvas.offsetWidth || window.innerWidth);
    let height = (canvas.height = canvas.offsetHeight || window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = canvas.offsetWidth || window.innerWidth;
      height = canvas.height = canvas.offsetHeight || window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    // Liquid Fluid Splats array
    const palette = [color0, color1, ...colors];
    const splats = [];
    const maxSplats = 45;

    for (let i = 0; i < maxSplats; i++) {
      splats.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * autoSpeed * 4,
        vy: (Math.random() - 0.5) * autoSpeed * 4,
        radius: (Math.random() * 80 + cursorSize) * resolution,
        color: palette[Math.floor(Math.random() * palette.length)],
        life: Math.random() * 1.5 + 0.5,
        maxLife: 2.0
      });
    }

    const mouse = {
      x: width / 2,
      y: height / 2,
      px: width / 2,
      py: height / 2,
      vx: 0,
      vy: 0,
      lastMoved: Date.now()
    };

    const handleMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      mouse.vx = (mx - mouse.x) * 0.4;
      mouse.vy = (my - mouse.y) * 0.4;
      mouse.px = mouse.x;
      mouse.py = mouse.y;
      mouse.x = mx;
      mouse.y = my;
      mouse.lastMoved = Date.now();

      // Add interactive mouse liquid splat
      if (Math.hypot(mouse.vx, mouse.vy) > 0.5) {
        splats.push({
          x: mouse.x,
          y: mouse.y,
          vx: mouse.vx * (mouseForce * 0.1),
          vy: mouse.vy * (mouseForce * 0.1),
          radius: cursorSize * 0.8,
          color: palette[Math.floor(Math.random() * palette.length)],
          life: 1.0,
          maxLife: 1.0
        });
        if (splats.length > maxSplats * 2) splats.shift();
      }
    };

    canvas.addEventListener('mousemove', handleMouseMove);

    let angle = 0;

    const render = () => {
      // Background base tint
      ctx.fillStyle = color2 || '#070b14';
      ctx.fillRect(0, 0, width, height);

      // Auto-demo fluid swirl movement if mouse inactive
      const timeSinceMouse = Date.now() - mouse.lastMoved;
      if (autoDemo && timeSinceMouse > autoResumeDelay) {
        angle += 0.02 * autoSpeed;
        const cx = width / 2 + Math.cos(angle) * (width * 0.25 * autoIntensity);
        const cy = height / 2 + Math.sin(angle * 1.5) * (height * 0.25 * autoIntensity);

        splats.push({
          x: cx,
          y: cy,
          vx: Math.cos(angle) * 3 * autoSpeed,
          vy: Math.sin(angle * 1.5) * 3 * autoSpeed,
          radius: cursorSize * 0.7,
          color: palette[Math.floor(Math.random() * palette.length)],
          life: 0.8,
          maxLife: 0.8
        });
        if (splats.length > maxSplats * 2) splats.shift();
      }

      // Render and diffuse liquid splats
      for (let i = splats.length - 1; i >= 0; i--) {
        const s = splats[i];
        s.x += s.vx;
        s.y += s.vy;
        s.vx *= 0.96; // Viscous dampening
        s.vy *= 0.96;
        s.life -= 0.015;

        if (s.life <= 0) {
          splats.splice(i, 1);
          continue;
        }

        const alpha = Math.max(0, s.life / s.maxLife);
        const radGrad = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, s.radius);
        radGrad.addColorStop(0, s.color);
        radGrad.addColorStop(0.6, s.color + 'aa');
        radGrad.addColorStop(1, 'transparent');

        ctx.save();
        ctx.globalCompositeOperation = 'screen';
        ctx.fillStyle = radGrad;
        ctx.globalAlpha = alpha * 0.65;
        ctx.beginPath();
        ctx.arc(s.x, s.y, s.radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
      }

      animFrameRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      canvas.removeEventListener('mousemove', handleMouseMove);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [
    colors, mouseForce, cursorSize, isViscous, viscous, resolution,
    autoDemo, autoSpeed, autoIntensity, autoResumeDelay, color0, color1, color2
  ]);

  return (
    <div className={`liquidether-container ${className}`} style={{ width: '100%', height: '100%', position: 'relative', overflow: 'hidden' }}>
      <canvas ref={canvasRef} className="liquidether-canvas" style={{ width: '100%', height: '100%', display: 'block' }} />
    </div>
  );
};

export default LiquidEther;
