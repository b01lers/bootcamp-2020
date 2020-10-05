--
-- classic
--
-- Copyright (c) 2014, rxi
--
-- This module is free software; you can redistribute it and/or modify it under
-- the terms of the MIT license. See LICENSE for details.
--


local Object = {}
Object.__index = Object


function Object:new()
end

function Object:checkProps(init, props)
    for key, val in pairs(props) do
        if init[val] == nil then
            error("Error: expected argument " .. key .. ":" .. val)
        end
    end
end

function Object:addAllProps(init)
    for key, val in pairs(init) do
        self[key] = init[key]
    end
end

function copy(obj, seen)
    if type(obj) ~= 'table' then
        return obj
    end

    if seen and seen[obj] then
        return seen[obj]
    end

    local s = seen or {}
    local res = {}
    s[obj] = res
    for k, v in pairs(obj) do
        res[copy(k, s)] = copy(v, s)
    end
    return setmetatable(res, getmetatable(obj))
end

function Object:extend()
  local cls = {}
  for k, v in pairs(self) do
    if k:find("__") == 1 then
      cls[k] = v
    end
  end
  cls.__index = cls
  cls.super = self
  setmetatable(cls, self)
  return cls
end


function Object:implement(...)
  for _, cls in pairs({...}) do
    for k, v in pairs(cls) do
      if self[k] == nil and type(v) == "function" then
        self[k] = v
      end
    end
  end
end


function Object:is(T)
  local mt = getmetatable(self)
  while mt do
    if mt == T then
      return true
    end
    mt = getmetatable(mt)
  end
  return false
end


function Object:__tostring()
  return "Object"
end


function Object:__call(...)
  local obj = setmetatable({}, self)
  obj:new(...)
  return obj
end


return Object
