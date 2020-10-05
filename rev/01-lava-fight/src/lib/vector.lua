Vector2 = Object:extend()

function Vector2:new(x, y)
    self.x = x
    self.y = y
end

function Vector2:normal()
    return Vector2(self.x / self:length(), self.y / self:length())
end

function Vector2:length()
    return math.sqrt((self.x * self.x) + (self.y * self.y))
end

function Vector2:resize(length)
    local norm = self:normal()
    return Vector2(norm.x * length, norm.y * length)
end

function Vector2:getQuadAt(x, y)
    return {x, y, self.x + x, self.y + y}
end

function Vector2:print()
    print("(", self.x, ",", self.y, ")")
end
