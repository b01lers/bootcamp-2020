function readFile(path)
    local f = assert(io.open(file, "rb"))
    local content = f:read("*all")
    f:close()
    return content
end

function newAnimation(name, image, width, height, duration)
    local animation = {}
    animation.name = name;
    animation.spriteSheet = image;
    animation.quads = {};
 
    for y = 0, image:getHeight() - height, height do
        for x = 0, image:getWidth() - width, width do
            q = love.graphics.newQuad(x, y, width, height, image:getDimensions())
            assert(q)
            table.insert(animation.quads, q)
        end
    end
 
    animation.duration = duration or 1
    animation.currentTime = 0
 
    return animation
end

function newImage(path)
    return love.graphics.newImage(path)
end

function printTable(tab)
    for k, v in pairs(tab) do
        if type(v) == "table" then
            print(k)
            printTable(v)
        else
            print(k, v)
        end
    end
end


