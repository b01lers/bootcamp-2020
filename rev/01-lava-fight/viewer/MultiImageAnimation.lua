MultiImageAnimation = Object:extend()
MultiImageIndexer = Object:extend()

function MultiImageAnimation:new(baseImagePath, count, extension, duration)
    self.imagePaths = {}
    self.images = {}
    self.currentImageIdx = 0
    self.currentTime = 0
    self.duration = duration or 1
    for i = 1, count do
        self.imagePaths[i] = baseImagePath .. i .. extension
    end

    for i, path in pairs(self.imagePaths) do
        self.images[i] = newImage(path)
    end
end

function MultiImageAnimation:update(dt)
    self.currentTime = self.currentTime + dt
    if self.currentTime >= self.duration then
        self.currentTime = self.currentTime - self.duration
    end
    self.currentImageIdx = math.floor(self.currentTime / self.duration * #self.images) + 1
end

function MultiImageAnimation:draw()
    love.graphics.draw(self.images[self.currentImageIdx], 0, 0)
end

function MultiImageIndexer:new(image, w, h, indices)
    self.image = newImage(image)
    self.quads = {}
    self.w = w
    self.h = h
    local idx = 1
    for y = 0, self.image:getHeight() - h, h do
        for x = 0, self.image:getWidth() - w, w do
            self.quads[indices[idx]] = love.graphics.newQuad(x, y, w, h, self.image:getDimensions())
            idx = idx + 1
        end
    end
end

function MultiImageIndexer:draw(index, x, y, scale)
    love.graphics.draw(self.image, self.quads[index], x, y, 0, scale, scale)
end
