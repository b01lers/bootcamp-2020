CollisionObject = Object:extend()

function CollisionObject:new(image, x, y)
    self.img_data = love.image.newImageData(image)
    self.w, self.h = self.img_data:getDimensions()
    self.x = x
    self.y = y
    self.img = love.graphics.newImage(self.img_data)
end

function CollisionObject:draw()
    love.graphics.draw(self.img, self.x, self.y)
end

function CollisionObject:setDamageObject()
    self.isDamageObject = true
end

function CollisionObject:move(x, y)
    self.x = self.x + x
    self.y = self.y + y
end

function CollisionObject:checkRectCollision(other)
    return self.x < other.x + other.w and
    self.x + self.w > other.x and
    self.y < other.y + other.h and
    self.h + self.y > other.y
end

function CollisionObject:getOverlappingRect(other)

    local x = math.max(self.x, other.x)
    local y = math.max(other.y, self.y)

    local w = math.min(self.w, other.w)
    local h = math.min(self.h, other.h)
    return x, y, w, h
end

function CollisionObject:getCollisionRects(other)
    if not self:checkRectCollision(other) then
        return 0, 0, 0, 0
    end

    local rx, ry, rw, rh = self:getOverlappingRect(other)
    return rx, ry, rw, rh
end

function CollisionObject:checkCollisionWith(other)
    if not self:checkRectCollision(other) then
        return false, false
    end

    local rx, ry, rw, rh = self:getOverlappingRect(other)

    local sx, sy, sdata = self.x, self.y, self.img_data
    local ox, oy, odata = other.x, other.y, other.img_data
    for x = rx, rx+rw-1 do
        for y = ry, ry+rh-1 do
            local dx = x - rx
            local dy = y - ry
            local _, _, _, sa = sdata:getPixel(clamp(rx-sx+dx, sdata:getWidth()), clamp(ry-sy+dy, sdata:getHeight()))
            local _, _, _, oa = odata:getPixel(clamp(rx-ox+dx, odata:getWidth()), clamp(ry-oy+dy, odata:getHeight()))
            if sa > 0 and oa > 0 then
                return true, true
            end
        end
    end
    return true, false
end

function clamp(val, max)
    if val > max then
        return max
    elseif val < 0 then
        return 0
    end
    return val
end

function CollisionObject:getCollisionWithBorder(border)
    local result = {
        ["left"] = {
            ["collision"] = false,
            ["damage"] = false
        },
        ["right"] = {
            ["collision"] = false,
            ["damage"] = false
        },
        ["top"] = {
            ["collision"] = false,
            ["damage"] = false
        },
        ["bottom"] = {
            ["collision"] = false,
            ["damage"] = false
        }
    }

    for _, dir in pairs({"left", "right", "top", "bottom"}) do
        for coord, _ in pairs(border[dir]) do
            x = math.floor(coord[1])
            y = math.floor(coord[2])
            x = clamp(x, self.img_data:getWidth() - 1)
            y = clamp(y, self.img_data:getHeight() - 1)
            local _, _, _, sa = self.img_data:getPixel(x, y)
            if sa > 0 then
                result[dir]["collision"] = true
                if self.isDamageObject then
                    result[dir]["damage"] = true
                end
            end
        end
    end
    return result
end

function CollisionObject:getBorder(img, quad)
    local sx, sy, sdata, h, w
    if img ~= nil and quad ~= nil then
        local tx, ty, tw, th = quad:getViewport()
        w, h = tw, th
        sdata = img:getData()
        sx = self.x + tx
        sy = self.y + ty
    else
        sx, sy, sdata = self.x, self.y, self.img_data
        h, w = self.h, self.w
    end
    local left, right, top, bottom = {}, {}, {}, {}
    for x = w / 3, (2 * w) / 3 do
        for y = 0, h - 1 do
            local _, _, _, sa = sdata:getPixel(x, y)
            if sa > 0 then
                top[{x+sx, y+sy}] = true
                break
            end
        end
        for y = h - 1, 0, -1 do
            local _, _, _, sa = sdata:getPixel(x, y)
            if sa > 0 then
                bottom[{x+sx, y+sy}] = true
                break
            end
        end
    end
    for y = h / 3, (2 * h) / 3 do
        for x = 0, w - 1 do
            local _, _, _, sa = sdata:getPixel(x, y)
            if sa > 0 then
                left[{x+sx, y+sy}] = true
                break
            end
        end
        for x = w - 1, 0, -1 do
            local _, _, _, sa = sdata:getPixel(x, y)
            if sa > 0 then
                right[{x+sx, y+sy}] = true
                break
            end
        end
    end
    local border = {["left"] = left, ["right"] = right, ["top"] = top, ["bottom"] = bottom}
    return border
end
