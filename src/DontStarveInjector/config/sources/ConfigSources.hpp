#pragma once
#include "config/IConfigSource.hpp"
#include "config/ConfigSchema.hpp"

namespace ds::config {

// Emits default_value for every schema entry (ModinfoDefault layer).
class ModinfoDefaultSource final : public IConfigSource {
public:
    explicit ModinfoDefaultSource(const ds::plugin::ConfigSchemaRegistry &schema);
    ConfigSource id() const override;
    ConfigPartial read(CascadeContext &ctx) const override;

private:
    const ds::plugin::ConfigSchemaRegistry &schema_;
};

// Wraps luajit_config::read_from_file → AlwaysEnableMod / DisableJITWhenServer.
// Also seeds CascadeContext identity (modmain_path / modname / modid) when present.
class LuajitConfigSource final : public IConfigSource {
public:
    ConfigSource id() const override;
    ConfigPartial read(CascadeContext &ctx) const override;
};

// Client modconfiguration_* save file (id == SaveFile).
class SaveFileSource final : public IConfigSource {
public:
    explicit SaveFileSource(const ds::plugin::ConfigSchemaRegistry &schema);
    ConfigSource id() const override;
    ConfigPartial read(CascadeContext &ctx) const override;

private:
    const ds::plugin::ConfigSchemaRegistry &schema_;
};

// Server modoverrides.lua (id == SaveFile).
class ModOverridesSource final : public IConfigSource {
public:
    explicit ModOverridesSource(const ds::plugin::ConfigSchemaRegistry &schema);
    ConfigSource id() const override;
    ConfigPartial read(CascadeContext &ctx) const override;

private:
    const ds::plugin::ConfigSchemaRegistry &schema_;
};

// Env / command line: LuaVmType + AngleBackend.
class EnvOrCmdSource final : public IConfigSource {
public:
    ConfigSource id() const override;
    ConfigPartial read(CascadeContext &ctx) const override;
};

} // namespace ds::config
