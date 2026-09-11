import React, { useRef, useEffect } from 'react';
import './AeroShards.css';

export const AeroShards = ({
  backgroundColor = "#120F17",
  shardColor = "#896ABD",
  accentColor = "#A855F7",
  placement = "full",
  flow = "stream",
  material = "pearl",
  detail = "balanced",
  effect = "none",
  scale = 1,
  spread = 1,
  depth = 1,
  speed = 1,
  spin = 1,
  interaction = "repel",
  density = 1.5,
  shardSize = 1.1,
  stretch = 1,
  turbulence = 1,
  glow = 1,
  edgeSoftness = 2,
  bloom = 0.5,
  grain = 0.05,
  chromaticAberration = 0.0075,
  transitionDuration = 1,
  interactionRadius = 1.5,
  interactionStrength = 0.5,
  rippleIntensity = 1,
  holdToGather = true,
  className = ""
}) => {
  const canvasRef = useRef(null);
  const animationFrameRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = (canvas.width = canvas.offsetWidth || window.innerWidth);
    let height = (canvas.height = canvas.offsetHeight || 600);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = canvas.offsetWidth || window.innerWidth;
      height = canvas.height = canvas.offsetHeight || 600;
    };
    window.addEventListener('resize', handleResize);

    const mouse = { x: width / 2, y: height / 2, isDown: false, targetX: width / 2, targetY: height / 2 };

    const handleMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      mouse.targetX = e.clientX - rect.left;
      mouse.targetY = e.clientY - rect.top;
    };

    const handleMouseDown = () => { mouse.isDown = true; };
    const handleMouseUp = () => { mouse.isDown = false; };

    canvas.addEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mouseup', handleMouseUp);

    // Particle / Shard pool initialization
    const count = Math.floor(60 * density * scale);
    const shards = [];

    for (let i = 0; i < count; i++) {
      shards.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * speed * 0.8,
        vy: (Math.random() - 0.5) * speed * 0.8 + 0.2,
        baseSize: (Math.random() * 12 + 8) * shardSize,
        angle: Math.random() * Math.PI * 2,
        vSpin: (Math.random() - 0.5) * 0.02 * spin,
        sides: Math.floor(Math.random() * 3) + 3, // 3 to 5 facets
        color: Math.random() > 0.4 ? shardColor : accentColor,
        opacity: Math.random() * 0.5 + 0.4,
        z: Math.random() * depth + 0.5,
      });
    }

    const render = () => {
      // Smooth mouse interpolation
      mouse.x += (mouse.targetX - mouse.x) * 0.1;
      mouse.y += (mouse.targetY - mouse.y) * 0.1;

      // Background fill
      ctx.fillStyle = backgroundColor;
      ctx.fillRect(0, 0, width, height);

      // Radial ambient glow
      const glowGrad = ctx.createRadialGradient(
        mouse.x, mouse.y, 10,
        mouse.x, mouse.y, 280 * interactionRadius
      );
      glowGrad.addColorStop(0, `${accentColor}25`);
      glowGrad.addColorStop(1, 'transparent');
      ctx.fillStyle = glowGrad;
      ctx.fillRect(0, 0, width, height);

      const radiusPx = 150 * interactionRadius;

      // Draw shards
      shards.forEach((s) => {
        // Stream flow movement
        s.x += s.vx * s.z + (Math.sin(s.y * 0.01 * turbulence) * 0.3 * speed);
        s.y += s.vy * s.z;
        s.angle += s.vSpin;

        // Wrap boundaries
        if (s.x < -40) s.x = width + 40;
        if (s.x > width + 40) s.x = -40;
        if (s.y < -40) s.y = height + 40;
        if (s.y > height + 40) s.y = -40;

        // Mouse interaction physics
        const dx = mouse.x - s.x;
        const dy = mouse.y - s.y;
        const dist = Math.hypot(dx, dy);

        if (dist < radiusPx && dist > 0) {
          const force = (1 - dist / radiusPx) * interactionStrength * 4;
          if (holdToGather && mouse.isDown) {
            // Attraction / gather mode on click
            s.x += (dx / dist) * force * 3;
            s.y += (dy / dist) * force * 3;
          } else if (interaction === 'repel') {
            // Repel mode
            s.x -= (dx / dist) * force * 4;
            s.y -= (dy / dist) * force * 4;
          }
        }

        // Render shard geometry with pearl material gradient
        ctx.save();
        ctx.translate(s.x, s.y);
        ctx.rotate(s.angle);
        ctx.scale(1, stretch);

        const sz = s.baseSize * s.z;
        ctx.beginPath();
        for (let i = 0; i < s.sides; i++) {
          const a = (i * 2 * Math.PI) / s.sides;
          const px = Math.cos(a) * sz;
          const py = Math.sin(a) * sz;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();

        // Pearl material gradient fill
        const shardGrad = ctx.createLinearGradient(-sz, -sz, sz, sz);
        shardGrad.addColorStop(0, s.color);
        shardGrad.addColorStop(0.7, accentColor);
        shardGrad.addColorStop(1, '#FFFFFF');

        ctx.fillStyle = shardGrad;
        ctx.globalAlpha = s.opacity;

        if (glow > 0) {
          ctx.shadowColor = accentColor;
          ctx.shadowBlur = 12 * glow;
        }

        ctx.fill();

        // Facet highlight stroke
        ctx.strokeStyle = `rgba(255, 255, 255, ${0.4 * s.opacity})`;
        ctx.lineWidth = 1;
        ctx.stroke();

        ctx.restore();
      });

      animationFrameRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      canvas.removeEventListener('mousemove', handleMouseMove);
      canvas.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mouseup', handleMouseUp);
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, [
    backgroundColor, shardColor, accentColor, speed, spin, interaction,
    density, shardSize, stretch, turbulence, glow, interactionRadius,
    interactionStrength, holdToGather, scale, depth
  ]);

  return (
    <div className={`aeroshards-container ${className}`} style={{ width: '100%', height: '100%', position: 'relative', overflow: 'hidden' }}>
      <canvas ref={canvasRef} className="aeroshards-canvas" style={{ width: '100%', height: '100%', display: 'block' }} />
    </div>
  );
};

export default AeroShards;
