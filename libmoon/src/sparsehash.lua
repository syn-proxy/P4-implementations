
local log = require "log"
local ffi = require "ffi"
ffi.cdef [[
struct _sparse_hash_map { };
struct _sparse_hash_map* mg_create_sparse_hash_map();
void mg_free_sparse_hash_map(struct _sparse_hash_map* map);

void mg_set_sparse_hash_map(struct _sparse_hash_map* map, const char* k, int v);
int mg_get_sparse_hash_map(struct _sparse_hash_map* map, const char* k);
void mg_erase_sparse_hash_map(struct _sparse_hash_map* map, const char* k);
]]

local mod = {}

local sparseHashMap = {}
sparseHashMap.__index = sparseHashMap

function mod.createSparseHashMap()
	log:info("Creating sparse hash map")
	return setmetatable({
		map = ffi.gc(ffi.C.mg_create_sparse_hash_map(), function (self)
			log:debug("Destroying sparse hash map")
			ffi.C.mg_free_sparse_hash_map(self)
		end)
	}, sparseHashMap)
end

function sparseHashMap:set(k, v)
	ffi.C.mg_set_sparse_hash_map(self.map, k, v)
end

function sparseHashMap:get(k)
	return ffi.C.mg_get_sparse_hash_map(self.map, k)
end

function sparseHashMap:erase(k)
	return ffi.C.mg_erase_sparse_hash_map(self.map, k)
end

return mod
