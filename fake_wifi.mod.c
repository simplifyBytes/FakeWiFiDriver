#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x1bff00c8, "kmalloc_caches" },
	{ 0xd0c3484c, "kmalloc_trace" },
	{ 0xbada1a7, "ieee80211_register_hw" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x122c3a7e, "_printk" },
	{ 0x2cf56265, "__dynamic_pr_debug" },
	{ 0xcda763d3, "cfg80211_inform_bss_data" },
	{ 0x5eb249ee, "cfg80211_put_bss" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3c12dfe, "cancel_work_sync" },
	{ 0x68e75509, "skb_queue_purge_reason" },
	{ 0xd72aeea0, "ieee80211_unregister_hw" },
	{ 0x37a0cba, "kfree" },
	{ 0x1e8f664c, "ieee80211_free_hw" },
	{ 0x192aba9e, "platform_device_unregister" },
	{ 0xd2e4ecca, "consume_skb" },
	{ 0x9645e4cf, "skb_dequeue" },
	{ 0xd599afbb, "__netdev_alloc_skb" },
	{ 0xde87b83, "skb_put" },
	{ 0xf6890c1b, "ieee80211_rx_napi" },
	{ 0x54b1fac6, "__ubsan_handle_load_invalid_value" },
	{ 0x5d3b8025, "skb_copy" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0xd513779, "skb_queue_tail" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0x2d3385d3, "system_wq" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0xb8aff722, "pcpu_hot" },
	{ 0x763c7343, "ieee80211_tx_status_skb" },
	{ 0x3c3fce39, "__local_bh_enable_ip" },
	{ 0xf7568b26, "platform_device_register_full" },
	{ 0x8e980808, "ieee80211_alloc_hw_nm" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0xe2fd41e5, "module_layout" },
};

MODULE_INFO(depends, "mac80211,cfg80211");


MODULE_INFO(srcversion, "211940BFC954E1A6173CAD1");
