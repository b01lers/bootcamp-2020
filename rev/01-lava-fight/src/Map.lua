Map = Object:extend()
BGLayer = Object:extend()
Rectangle = Object:extend()
json = require("lib/json")

function Rectangle:new(x, y, w, h, d)
    self.x = x
    self.y = y
    self.w = w
    self.h = h
    self.damage = d
end

function BGLayer:new(image, x, y)
    self.img_data = love.image.newImageData(image)
    self.w, self.h = self.img_data:getDimensions()
    self.x = x
    self.y = y
    self.img = love.graphics.newImage(self.img_data)
    self.isDamageObject = false
end

function BGLayer:draw()
    love.graphics.draw(self.img, self.x, self.y)
end

function BGLayer:move(x, y)
    self.x = self.x + x
    self.y = self.y + y
end

function Map:mkSpritePath(val)
    local name = "maps/" .. val .. ".png"
    return name
end

function Map:newCollisionLayer(spritePath)
    local layer = CollisionObject(spritePath, 0, 0)
    return layer
end

function Map:newBackgroundLayer(spritePath)
    local layer = BGLayer(spritePath, 0, 0)
    return layer
end

function Map:newDamageLayer(spritePath)
    local layer = self:newCollisionLayer(spritePath)
    layer:setDamageObject()
    return layer
end

function Map:new(foregroundSprites, damageSprites, backgroundSprites, spawnPoints)
    self.layers = {}

    for _, sprite in pairs(backgroundSprites) do
        table.insert(self.layers, self:newBackgroundLayer(self:mkSpritePath(sprite)))
    end

    for _, sprite in pairs(damageSprites) do
        table.insert(self.layers, self:newDamageLayer(self:mkSpritePath(sprite)))
    end

    for _, sprite in pairs(foregroundSprites) do
        table.insert(self.layers, self:newCollisionLayer(self:mkSpritePath(sprite)))
    end
    self.spawnPoints = spawnPoints
end

function Map:update(x, y)
    for _, layer in pairs(self.layers) do
        layer:move(x, y)
    end
end

function Map:draw()
    for _, layer in pairs(self.layers) do
        layer:draw()
    end
end

function Map:checkCollisionDamage(other)
    local collision, damage = false, false
    for _, layer in pairs(self.layers) do
        if layer:is(CollisionObject) then
            local bbcol, ppcol = layer:checkCollisionWith(other)
            if ppcol then
                collision = true
            end

            if ppcol and layer.isDamageObject then
                damage = true
            end
        end
    end
    return collision, damage
end

function Map:getBorderCollision(border)
    local results = {}
    for _, layer in pairs(self.layers) do
        if layer:is(CollisionObject) then
            table.insert(results, layer:getCollisionWithBorder(border))
        end
    end
    return results
end

function Map:getCollisionRects(other)
    local collisionRects = {}
    for _, layer in pairs(self.layers) do
        if layer:is(CollisionObject) then
            local x, y, w, h = layer:getCollisionRects(layer)
            if w ~= 0 and h ~= 0 then
                table.insert(collisionRects, Rectangle(x, y, w, h, layer.isDamageObject))
            end
        end
    end
    return collisionrects
end

function Map:getRandomSpawnPoint()
    local spi = love.math.random(1, #self.spawnPoints)
    --printTable(self.spawnPoints[spi])
    return unpack(self.spawnPoints[spi])
end

