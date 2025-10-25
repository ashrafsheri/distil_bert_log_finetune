# 🎨 Frontend Style Quick Reference

## CSS Classes Added

### Glassmorphism
```css
.glass             - Semi-transparent with blur
.glass-strong      - More opaque with stronger blur
```

### Gradients
```css
.gradient-text     - Blue to cyan gradient text
```

### Animations
```css
.animate-fade-in   - Fade in effect
.animate-slide-up  - Slide up from bottom
.animate-slide-down - Slide down from top
.animate-scale-in  - Scale up from center
.animate-float     - Subtle floating motion
.card-hover        - Hover lift effect for cards
.stagger-1/2/3/4   - Animation delay (0.1s increments)
```

## Color Variables (Tailwind)

### Theme Colors
```
vt-dark       #1a1a2e  - Main background
vt-blue       #16213e  - Surface/panels
vt-primary    #7B9EFF  - Primary actions
vt-light      #f5f5f5  - Text
vt-muted      #A0A8C0  - Secondary text
vt-error      #e94560  - Errors/threats
vt-success    #10B981  - Success/safe
vt-warning    #F59E0B  - Warnings
```

## Common Patterns

### Card with Glassmorphism
```tsx
<div className="glass-strong rounded-2xl border border-vt-primary/30 p-6 card-hover">
  {/* Content */}
</div>
```

### Gradient Icon Container
```tsx
<div className="w-12 h-12 bg-gradient-to-br from-vt-primary to-vt-success rounded-xl flex items-center justify-center shadow-lg">
  <svg className="w-6 h-6 text-white">...</svg>
</div>
```

### Enhanced Badge
```tsx
<span className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-vt-success/20 text-vt-success border border-vt-success/30 shadow-sm">
  ✓ Status
</span>
```

### Gradient Progress Bar
```tsx
<div className="w-full bg-vt-muted/20 rounded-full h-3 overflow-hidden border border-vt-muted/30">
  <div
    className="h-full rounded-full transition-all duration-500"
    style={{
      width: '75%',
      background: 'linear-gradient(90deg, #10B981 0%, #059669 100%)'
    }}
  />
</div>
```

### Gradient Button
```tsx
<button className="px-6 py-3 bg-gradient-to-r from-vt-primary to-vt-success text-white font-bold rounded-xl shadow-lg hover:shadow-2xl hover:scale-105 transition-all">
  Click Me
</button>
```

### Section Header
```tsx
<div className="flex items-center gap-3 mb-4">
  <div className="w-1 h-6 bg-gradient-to-b from-vt-primary to-vt-success rounded-full"></div>
  <h4 className="text-lg font-bold text-vt-light">Title</h4>
</div>
```

### Status Indicator (Live)
```tsx
<div className="flex items-center gap-3">
  <div className="relative w-3 h-3 rounded-full bg-vt-success">
    <span className="absolute inset-0 rounded-full bg-vt-success animate-ping"></span>
  </div>
  <span>Live</span>
</div>
```

### Empty State
```tsx
<div className="flex items-center justify-center py-20">
  <div className="text-center animate-fade-in">
    <div className="w-20 h-20 bg-gradient-to-br from-vt-muted/20 to-vt-muted/10 rounded-2xl flex items-center justify-center mx-auto mb-6">
      <svg className="w-10 h-10 text-vt-muted">...</svg>
    </div>
    <p className="text-vt-light font-semibold text-lg">No data</p>
    <p className="text-vt-muted text-sm mt-2">Waiting for content...</p>
  </div>
</div>
```

## Animation Timings

```
Fast:    200ms - Hovers, clicks
Medium:  300ms - Transitions, slides
Slow:    500ms - Entrance effects
```

## Responsive Breakpoints

```
sm:  640px   - Small tablets
md:  768px   - Tablets
lg:  1024px  - Small laptops
xl:  1280px  - Desktops
2xl: 1536px  - Large screens
```

## Best Practices

### Do's ✅
- Use glassmorphism for containers
- Add gradient icons for visual interest
- Include hover effects on interactive elements
- Use consistent spacing (gap-3, gap-4, gap-6)
- Apply smooth transitions (transition-all)
- Add borders to glassmorphic elements
- Use rounded-xl or rounded-2xl for cards
- Include shadow effects (shadow-lg, shadow-2xl)

### Don'ts ❌
- Don't mix solid and glass backgrounds
- Don't use too many different gradients
- Don't forget hover states
- Don't use sharp corners on cards
- Don't skip animation timing
- Don't overuse animations

## Spacing Scale

```
gap-1: 0.25rem (4px)
gap-2: 0.5rem  (8px)
gap-3: 0.75rem (12px)
gap-4: 1rem    (16px)
gap-6: 1.5rem  (24px)
gap-8: 2rem    (32px)
```

## Border Radius

```
rounded-lg:  0.5rem  (8px)
rounded-xl:  0.75rem (12px)
rounded-2xl: 1rem    (16px)
rounded-full: 9999px (Circle)
```

## Shadow Variants

```
shadow-sm   - Subtle
shadow-lg   - Standard
shadow-xl   - Prominent
shadow-2xl  - Very prominent
```

## Icon Sizes

```
w-4 h-4  - Small (16px)
w-5 h-5  - Medium (20px)
w-6 h-6  - Large (24px)
w-8 h-8  - Extra Large (32px)
w-10 h-10 - Container size
w-12 h-12 - Header size
```

## Typography

```
text-xs   - 0.75rem (12px)
text-sm   - 0.875rem (14px)
text-base - 1rem (16px)
text-lg   - 1.125rem (18px)
text-xl   - 1.25rem (20px)
text-2xl  - 1.5rem (24px)
text-3xl  - 1.875rem (30px)
text-4xl  - 2.25rem (36px)
```

## Font Weights

```
font-medium   - 500
font-semibold - 600
font-bold     - 700
```

---

*Quick reference for maintaining consistent styling across the LogGuard frontend*
