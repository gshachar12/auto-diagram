import random
import colorsys
from palettable.cartocolors.qualitative import Bold_6

def lighten_hex_color(hex_str, factor=0.8): # Changed default to 0.8 for extra brightness
    """Takes a hex color string and returns an extra lightened version."""
    hex_str = hex_str.lstrip('#')
    r, g, b = tuple(int(hex_str[i:i+2], 16) for i in (0, 2, 4))
    
    # Normalize to 0.0 - 1.0
    r_norm, g_norm, b_norm = r / 255.0, g / 255.0, b / 255.0
    
    # Convert to HLS, boost lightness significantly, and convert back
    h, l, s = colorsys.rgb_to_hls(r_norm, g_norm, b_norm)
    new_l = l + (1.0 - l) * factor
    new_r, new_g, new_b = colorsys.hls_to_rgb(h, new_l, s)
    
    return f"#{int(new_r * 255):02x}{int(new_g * 255):02x}{int(new_b * 255):02x}"
def lighten_color_list(hex_colors, factor=0.8): # Changed default to 0.8 for extra brightness
    """Lightens a list of hex colors by the given factor."""
    return [lighten_hex_color(color, factor) for color in hex_colors]


def hex_to_rgb(hex_str):
    """Helper to convert hex to RGB tuple for ANSI colors."""
    hex_str = hex_str.lstrip('#')
    return tuple(int(hex_str[i:i+2], 16) for i in (0, 2, 4))

def random_color_from_palette(palette=Bold_6):
    """Selects a random color from the provided palette."""
    return random.choice(palette.hex_colors)
def select_random_colors(num_colors, palette=Bold_6):
    """Selects a random subset of colors from the provided list."""
    if num_colors > len(palette.hex_colors):
        raise ValueError("Requested more colors than available in the palette.")
    return random.sample(palette.hex_colors, num_colors)

def display_super_light_preview(palette_name, hex_colors):
    """Displays a preview focusing on extra light fill variations."""
    print(f"\n=== Extra Light Pairing Preview: {palette_name} ===")
    print(f"{'Stroke (Dark)':<18} | {'Fill (Extra Light)':<18}")
    print("-" * 48)
    
    for color in hex_colors:
        # Generate the extra light fill color (factor 0.8)
        super_light_color = lighten_hex_color(color, factor=0.8)
        
        # Get RGB components
        r_d, g_d, b_d = hex_to_rgb(color)
        r_l, g_l, b_l = hex_to_rgb(super_light_color)
        
        # Visual blocks
        dark_block = f"\033[48;2;{r_d};{g_d};{b_d}m      \033[0m"
        light_block = f"\033[48;2;{r_l};{g_l};{b_l}m      \033[0m"
        
        print(f"  {dark_block} {color:<10} |   {light_block} {super_light_color:<10}")
    print("=" * (34 + len(palette_name)))

