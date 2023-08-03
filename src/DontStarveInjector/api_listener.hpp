#pragma once
#if USE_LISTENER
#include "frida-gum.h"

#include <lua.hpp>

typedef struct _ExampleListener ExampleListener;

struct _ExampleListener
{
	GObject parent;
	bool inlua;
	const char *entry_name;
	lua_State *L;
};

static void example_listener_iface_init(gpointer g_iface, gpointer iface_data);

#define EXAMPLE_TYPE_LISTENER (example_listener_get_type())
G_DECLARE_FINAL_TYPE(ExampleListener, example_listener, EXAMPLE, LISTENER, GObject)
G_DEFINE_TYPE_EXTENDED(ExampleListener,
					   example_listener,
					   G_TYPE_OBJECT,
					   0,
					   G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
											 example_listener_iface_init))

static bool inlua_module(GumInvocationContext *ic)
{
	auto return_addr = gum_invocation_context_get_return_address(ic);
	gchar *path;
	GumMemoryRange range;
	if (!gum_process_resolve_module_pointer(return_addr, &path, &range))
	{
		return false;
	}
	auto ret = std::string_view(path).find(luajitModuleName) != std::string_view::npos;
	g_free(path);
	return ret;
}

struct listen_info
{
	short name;
	int top;
	bool enter;
};

struct Listen_info_manager
{
	std::atomic_short name_id = 0;
	std::unordered_map<short, std::string> name_map;
	std::unordered_map<const char *, short> name_to_id;
	std::list<listen_info> infos;
	void push_info(const char *name, int top, bool enter)
	{
		short id = 0;
		auto iter = name_to_id.find(name);
		if (iter == name_to_id.end())
		{
			id = name_to_id.emplace(name, name_id++).second;
		}
		else
		{
			id = iter->second;
		}
		infos.emplace_back(listen_info{id, top, enter});
	}
	~Listen_info_manager()
	{
		auto File = fopen("listen.txt", "w");
		for (const auto &info : infos)
		{
			auto name = name_map[info.name];
			fprintf(File, "%s: %s[%d]", info.enter ? "e" : "l", name.c_str(), info.top);
		}
	}
};
static Listen_info_manager listen_info_manager;

static void
example_listener_on_enter(GumInvocationListener *listener,
						  GumInvocationContext *ic)
{
	ExampleListener *self = EXAMPLE_LISTENER(listener);
	if (self->inlua)
		return;
	auto name = GUM_IC_GET_FUNC_DATA(ic, const char *);
	self->inlua = !inlua_module(ic);
	self->L = (lua_State *)gum_invocation_context_get_nth_argument(ic, 0);
	listen_info_manager.push_info(name, lua_gettop(self->L), true);
}

static void
example_listener_on_leave(GumInvocationListener *listener,
						  GumInvocationContext *ic)
{
	ExampleListener *self = EXAMPLE_LISTENER(listener);

	if (self->inlua)
		self->inlua = inlua_module(ic);
	if (!self->inlua)
	{
		int top = lua_gettop(self->L);
		auto name = GUM_IC_GET_FUNC_DATA(ic, const char *);
		listen_info_manager.push_info(name, top, false);
	}
}

static void
example_listener_class_init(ExampleListenerClass *klass)
{
}

static void
example_listener_iface_init(gpointer g_iface,
							gpointer iface_data)
{
	GumInvocationListenerInterface *iface = (GumInvocationListenerInterface *)g_iface;

	iface->on_enter = example_listener_on_enter;
	iface->on_leave = example_listener_on_leave;
}

static void
example_listener_init(ExampleListener *self)
{
}
#endif