#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

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



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xe8213e80, "_printk" },
	{ 0x23f25c0a, "__dynamic_pr_debug" },
	{ 0x2d88a3ab, "cancel_work_sync" },
	{ 0x7383f816, "skb_queue_purge_reason" },
	{ 0x5a7d0b06, "ieee80211_unregister_hw" },
	{ 0x5a7d0b06, "ieee80211_free_hw" },
	{ 0x1bfe0859, "skb_dequeue" },
	{ 0x51967bdf, "__netdev_alloc_skb" },
	{ 0x431dfb05, "skb_put" },
	{ 0x8c96f55a, "ieee80211_rx_napi" },
	{ 0x33b8f8de, "consume_skb" },
	{ 0xf0cfe9d5, "pcpu_hot" },
	{ 0x766bc793, "ieee80211_tx_status_skb" },
	{ 0xfcc2e8f3, "__local_bh_enable_ip" },
	{ 0x0c82a447, "skb_copy" },
	{ 0xde338d9a, "_raw_spin_lock" },
	{ 0x0afadccc, "skb_queue_tail" },
	{ 0xde338d9a, "_raw_spin_unlock" },
	{ 0xaef1f20d, "system_wq" },
	{ 0x49733ad6, "queue_work_on" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0xec7abea5, "ieee80211_register_hw" },
	{ 0xd7ff10c8, "ieee80211_alloc_hw_nm" },
	{ 0xca0902b2, "ieee80211_emulate_add_chanctx" },
	{ 0x60feda35, "ieee80211_emulate_remove_chanctx" },
	{ 0x61e0e7e3, "ieee80211_emulate_change_chanctx" },
	{ 0x029d7f85, "ieee80211_emulate_switch_vif_chanctx" },
	{ 0xd272d446, "__fentry__" },
	{ 0x058c185a, "jiffies" },
	{ 0xab006604, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xd272d446,
	0xd272d446,
	0xe8213e80,
	0x23f25c0a,
	0x2d88a3ab,
	0x7383f816,
	0x5a7d0b06,
	0x5a7d0b06,
	0x1bfe0859,
	0x51967bdf,
	0x431dfb05,
	0x8c96f55a,
	0x33b8f8de,
	0xf0cfe9d5,
	0x766bc793,
	0xfcc2e8f3,
	0x0c82a447,
	0xde338d9a,
	0x0afadccc,
	0xde338d9a,
	0xaef1f20d,
	0x49733ad6,
	0xe4de56b4,
	0xec7abea5,
	0xd7ff10c8,
	0xca0902b2,
	0x60feda35,
	0x61e0e7e3,
	0x029d7f85,
	0xd272d446,
	0x058c185a,
	0xab006604,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__x86_return_thunk\0"
	"__stack_chk_fail\0"
	"_printk\0"
	"__dynamic_pr_debug\0"
	"cancel_work_sync\0"
	"skb_queue_purge_reason\0"
	"ieee80211_unregister_hw\0"
	"ieee80211_free_hw\0"
	"skb_dequeue\0"
	"__netdev_alloc_skb\0"
	"skb_put\0"
	"ieee80211_rx_napi\0"
	"consume_skb\0"
	"pcpu_hot\0"
	"ieee80211_tx_status_skb\0"
	"__local_bh_enable_ip\0"
	"skb_copy\0"
	"_raw_spin_lock\0"
	"skb_queue_tail\0"
	"_raw_spin_unlock\0"
	"system_wq\0"
	"queue_work_on\0"
	"__ubsan_handle_load_invalid_value\0"
	"ieee80211_register_hw\0"
	"ieee80211_alloc_hw_nm\0"
	"ieee80211_emulate_add_chanctx\0"
	"ieee80211_emulate_remove_chanctx\0"
	"ieee80211_emulate_change_chanctx\0"
	"ieee80211_emulate_switch_vif_chanctx\0"
	"__fentry__\0"
	"jiffies\0"
	"module_layout\0"
;

MODULE_INFO(depends, "mac80211");


MODULE_INFO(srcversion, "4471DF441A9685A64433A79");
