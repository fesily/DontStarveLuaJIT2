#pragma once
#include <frida-gum.h>
namespace Gum {
    struct InvocationListener
    {
      virtual ~InvocationListener () {}
  
      virtual void on_enter (GumInvocationContext * context) = 0;
      virtual void on_leave (GumInvocationContext * context) = 0;
    };
    
    typedef struct _GumInvocationListenerProxy GumInvocationListenerProxy;

    class InvocationListenerProxy
    {
    public:
      InvocationListenerProxy (InvocationListener * listener);
      virtual ~InvocationListenerProxy ();
  
      virtual void on_enter (GumInvocationContext * context);
      virtual void on_leave (GumInvocationContext * context);
  
      GumInvocationListenerProxy * cproxy;
      InvocationListener * listener;
    };



    class InvocationListenerProxy;

    typedef struct _GumInvocationListenerProxyClass GumInvocationListenerProxyClass;

    struct _GumInvocationListenerProxy {
        GObject parent;
        InvocationListenerProxy *proxy;
    };

    struct _GumInvocationListenerProxyClass {
        GObjectClass parent_class;
    };

    static GType gum_invocation_listener_proxy_get_type();
    static void gum_invocation_listener_proxy_iface_init(gpointer g_iface, gpointer iface_data);

    InvocationListenerProxy::InvocationListenerProxy(InvocationListener *listener)
        : cproxy(static_cast<GumInvocationListenerProxy *>(g_object_new(gum_invocation_listener_proxy_get_type(), NULL))),
            listener(listener) {
        cproxy->proxy = this;
    }

    InvocationListenerProxy::~InvocationListenerProxy() {
        g_object_unref(cproxy);
        delete listener;
    }

    void InvocationListenerProxy::on_enter(GumInvocationContext *context) {
        listener->on_enter(context);
    }

    void InvocationListenerProxy::on_leave(GumInvocationContext *context) {
        listener->on_leave(context);
    }
""
    G_DEFINE_TYPE_EXTENDED(GumInvocationListenerProxy,
                            gum_invocation_listener_proxy,
                            G_TYPE_OBJECT,
                            0,
                            G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
                                                    gum_invocation_listener_proxy_iface_init))

    static void
    gum_invocation_listener_proxy_init(GumInvocationListenerProxy *self) {
    }

    static void
    gum_invocation_listener_proxy_finalize(GObject *obj) {
        delete reinterpret_cast<GumInvocationListenerProxy *>(obj)->proxy;

        G_OBJECT_CLASS(gum_invocation_listener_proxy_parent_class)->finalize(obj);
    }

    static void
    gum_invocation_listener_proxy_class_init(GumInvocationListenerProxyClass *klass) {
        G_OBJECT_CLASS(klass)->finalize = gum_invocation_listener_proxy_finalize;
    }

    static void
    gum_invocation_listener_proxy_on_enter(GumInvocationListener *listener,
                                            GumInvocationContext *context) {
        reinterpret_cast<GumInvocationListenerProxy *>(listener)->proxy->on_enter(context);
    }

    static void
    gum_invocation_listener_proxy_on_leave(GumInvocationListener *listener,
                                            GumInvocationContext *context) {
        reinterpret_cast<GumInvocationListenerProxy *>(listener)->proxy->on_leave(context);
    }

    static void
    gum_invocation_listener_proxy_iface_init(gpointer g_iface,
                                                gpointer iface_data) {
        GumInvocationListenerInterface *iface =
                static_cast<GumInvocationListenerInterface *>(g_iface);

        iface->on_enter = gum_invocation_listener_proxy_on_enter;
        iface->on_leave = gum_invocation_listener_proxy_on_leave;
    }
}// namespace Gum