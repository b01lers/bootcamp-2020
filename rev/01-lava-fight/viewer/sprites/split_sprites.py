names = [
    "hole_top_left",
    "hole_top_mid",
    "hole_top_right",
    "flat_v1",
    "rocks_dark_v1",
    "rocks_dark_v2",
    "rocks_dark_v3",
    "rocks_dark_v4",
    "hole_left_mid",
    "hole_center",
    "hole_right_mid",
    "blank_v1",
    "flat_v2",
    "flat_v3",
    "rock_clump",
    "blank_v2",
    "hole_left_bottom",
    "hole_bottom_mid",
    "hole_right_bottom",
    "flat_v4",
    "flat_v5",
    "stalagmite_left",
    "stalagmite_mid",
    "stalagmite_right",
    "rock_pile_top_left",
    "rock_pile_top_mid",
    "rock_pile_top_right",
    "dark_hole_top_left",
    "dark_hole_top_right",
    "platform_left",
    "platform_mid",
    "platform_right",
    "rock_pile_left_mid",
    "rock_pile_center",
    "rock_pile_right_mid",
    "dark_hole_bottom_left",
    "dark_hole_bottom_right",
    "skull_v1",
    "skull_v2",
    "platform_single",
    "rock_pile_left_bottom",
    "rock_pile_bottom_middle",
    "rock_pile_right_bottom",
    "blank_v3",
    "blank_v4",
    "stalagtite_left",
    "stalagtite_mid",
    "stalagtite_right",
    "brick_v1",
    "brick_v2",
    "round_rock_left",
    "spike_right",
    "angle_shallow_up_left",
    "angle_shallow_up_right",
    "angle_shallow_down_left",
    "angle_shallow_down_right",
    "brick_v3",
    "brick_v4",
    "spike_left",
    "round_rock_right",
    "pillar_top",
    "blank_v5",
    "angle_up",
    "angle_down",
    "brick_v5",
    "brick_v6",
    "spike_up",
    "round_rock_up",
    "pillar_mid",
    "fence_top_left",
    "fence_top_mid",
    "fence_top_right",
    "lava_pool",
    "lava_fall",
    "blank_v6",
    "spike_down",
    "pillar_bottom",
    "fence_bottom_left",
    "fence_bottom_mid",
    "fence_bottom_right"
]

from PIL import Image
import os

def crop(infile,height,width):
    im = Image.open(infile)
    imgwidth, imgheight = im.size
    for i in range(imgheight//height):
        for j in range(imgwidth//width):
            box = (j*width, i*height, (j+1)*width, (i+1)*height)
            yield im.crop(box)

if __name__=='__main__':
    infile="./tiles/lava_tileset.png"
    height=16
    width=16
    start_num=0
    for k,piece in enumerate(crop(infile,height,width),start_num):
        img=Image.new('RGB', (height,width), 255)
        img.paste(piece)
        path=os.path.join('./tileset',names[k] + '.png')
        img.save(path)
