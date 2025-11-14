# CSS Structure

This directory contains all the CSS files for the Weather App, organized by functionality.

## File Structure

- `index.css` - Main CSS file that imports all other CSS files
- `reset.css` - CSS reset and base styles
- `scrollbar.css` - Custom scrollbar styles
- `glass.css` - Glass morphism effect styles
- `animations.css` - Animation classes and keyframes
- `responsive.css` - Responsive design media queries
- `weather.css` - Weather-specific background gradients

## Usage

Import the main CSS file in your main entry point:

```javascript
import './assets/css/index.css';
```

## Adding New Styles

1. Create a new CSS file for your specific functionality
2. Import it in `index.css`
3. Follow the existing naming conventions and structure

## Best Practices

- Use CSS modules or styled-components for component-specific styles
- Keep global styles in this directory
- Use semantic class names
- Follow the existing color scheme and design patterns
