/*
 * Fake Wi-Fi Driver - A SoftMAC driver for testing
 * Based on ath9k architecture but without real hardware
 * 
 * This driver demonstrates how to:
 * 1. Register with mac80211 as a SoftMAC driver
 * 2. Handle probe requests from userspace
 * 3. Generate fake probe responses
 * 4. Interact with the mac80211 subsystem
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ieee80211.h>
#include <net/mac80211.h>
#include <net/cfg80211.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/platform_device.h>
#include<net/mac80211.h>

#define FAKE_WIFI_DRIVER_NAME "fake_wifi"
#define FAKE_WIFI_VERSION "1.0"


/* Global hardware pointer for proper cleanup */
static struct ieee80211_hw *global_hw = NULL;

/* Fake hardware capabilities */
#define FAKE_WIFI_MAX_TX_POWER    20  /* dBm */
#define FAKE_WIFI_CHANNEL_2GHZ    6   /* Channel 6 (2437 MHz) */
#define FAKE_WIFI_CHANNEL_5GHZ    36  /* Channel 36 (5180 MHz) */

/* Fake AP configuration */
#define FAKE_AP_SSID "SimplifyBytesAP"
#define FAKE_AP_BSSID "\xaa\xbb\xcc\xdd\x11\x22"  /* Locally administered MAC */

/* Rate control constants - simplified from ath5k */
#define FAKE_WIFI_RATE_CODE_1M		0x1B
#define FAKE_WIFI_RATE_CODE_2M		0x1A
#define FAKE_WIFI_RATE_CODE_5_5M	0x19
#define FAKE_WIFI_RATE_CODE_11M		0x18
#define FAKE_WIFI_RATE_CODE_6M		0x0B
#define FAKE_WIFI_RATE_CODE_9M		0x0F
#define FAKE_WIFI_RATE_CODE_12M		0x0A
#define FAKE_WIFI_RATE_CODE_18M		0x0E
#define FAKE_WIFI_RATE_CODE_24M		0x09
#define FAKE_WIFI_RATE_CODE_36M		0x0D
#define FAKE_WIFI_RATE_CODE_48M		0x08
#define FAKE_WIFI_RATE_CODE_54M		0x0C
#define FAKE_WIFI_SET_SHORT_PREAMBLE	0x04

/*
 * Comprehensive rate table similar to ath5k_rates
 * This prevents rate control algorithm selection (like minstrel_ht)
 * by providing a complete set of supported rates
 */
static const struct ieee80211_rate fake_wifi_rates[] = {
	/* 802.11b rates */
	{ .bitrate = 10,
	  .hw_value = FAKE_WIFI_RATE_CODE_1M, },
	{ .bitrate = 20,
	  .hw_value = FAKE_WIFI_RATE_CODE_2M,
	  .hw_value_short = FAKE_WIFI_RATE_CODE_2M | FAKE_WIFI_SET_SHORT_PREAMBLE,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	{ .bitrate = 55,
	  .hw_value = FAKE_WIFI_RATE_CODE_5_5M,
	  .hw_value_short = FAKE_WIFI_RATE_CODE_5_5M | FAKE_WIFI_SET_SHORT_PREAMBLE,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	{ .bitrate = 110,
	  .hw_value = FAKE_WIFI_RATE_CODE_11M,
	  .hw_value_short = FAKE_WIFI_RATE_CODE_11M | FAKE_WIFI_SET_SHORT_PREAMBLE,
	  .flags = IEEE80211_RATE_SHORT_PREAMBLE },
	/* 802.11g rates */
	{ .bitrate = 60,
	  .hw_value = FAKE_WIFI_RATE_CODE_6M,
	  .flags = IEEE80211_RATE_SUPPORTS_5MHZ |
		   IEEE80211_RATE_SUPPORTS_10MHZ },
	{ .bitrate = 90,
	  .hw_value = FAKE_WIFI_RATE_CODE_9M,
	  .flags = IEEE80211_RATE_SUPPORTS_5MHZ |
		   IEEE80211_RATE_SUPPORTS_10MHZ },
	{ .bitrate = 120,
	  .hw_value = FAKE_WIFI_RATE_CODE_12M,
	  .flags = IEEE80211_RATE_SUPPORTS_5MHZ |
		   IEEE80211_RATE_SUPPORTS_10MHZ },
	{ .bitrate = 180,
	  .hw_value = FAKE_WIFI_RATE_CODE_18M,
	  .flags = IEEE80211_RATE_SUPPORTS_5MHZ |
		   IEEE80211_RATE_SUPPORTS_10MHZ },
	{ .bitrate = 240,
	  .hw_value = FAKE_WIFI_RATE_CODE_24M,
	  .flags = IEEE80211_RATE_SUPPORTS_5MHZ |
		   IEEE80211_RATE_SUPPORTS_10MHZ },
	{ .bitrate = 360,
	  .hw_value = FAKE_WIFI_RATE_CODE_36M,
	  .flags = IEEE80211_RATE_SUPPORTS_5MHZ |
		   IEEE80211_RATE_SUPPORTS_10MHZ },
	{ .bitrate = 480,
	  .hw_value = FAKE_WIFI_RATE_CODE_48M,
	  .flags = IEEE80211_RATE_SUPPORTS_5MHZ |
		   IEEE80211_RATE_SUPPORTS_10MHZ },
	{ .bitrate = 540,
	  .hw_value = FAKE_WIFI_RATE_CODE_54M,
	  .flags = IEEE80211_RATE_SUPPORTS_5MHZ |
		   IEEE80211_RATE_SUPPORTS_10MHZ },
};

#define FAKE_WIFI_NUM_RATES ARRAY_SIZE(fake_wifi_rates)

/* Driver private data structure */
struct fake_wifi_priv {
	struct ieee80211_hw *hw;
	struct ieee80211_vif *vif;
	
	/* Fake hardware state */
	bool hw_started;
	u32 current_channel;
	
	/* Probe response handling */
	struct work_struct probe_response_work;
	struct sk_buff_head probe_queue;
	spinlock_t probe_lock;
	
	/* Statistics */
	u32 probe_requests_received;
	u32 probe_responses_sent;
};

/* Forward declarations */
static int fake_wifi_start(struct ieee80211_hw *hw);
static void fake_wifi_stop(struct ieee80211_hw *hw, bool suspend);
static void fake_wifi_stop_wrapper(struct ieee80211_hw *hw);
static void fake_wifi_tx(struct ieee80211_hw *hw,
			 struct ieee80211_tx_control *control,
			 struct sk_buff *skb);
static int fake_wifi_config(struct ieee80211_hw *hw, u32 changed);
static void fake_wifi_configure_filter(struct ieee80211_hw *hw,
				       unsigned int changed_flags,
				       unsigned int *total_flags,
				       u64 multicast);
static int fake_wifi_add_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
static void fake_wifi_remove_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
static int fake_wifi_change_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				      enum nl80211_iftype new_type, bool p2p);
static int fake_wifi_sta_state(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			       struct ieee80211_sta *sta, enum ieee80211_sta_state old_state,
			       enum ieee80211_sta_state new_state);
static void fake_wifi_sta_notify(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				 enum sta_notify_cmd cmd, struct ieee80211_sta *sta);
static int fake_wifi_conf_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			     unsigned int ac, u16 queue,
			     const struct ieee80211_tx_queue_params *params);
static void fake_wifi_bss_info_changed(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				       struct ieee80211_bss_conf *info, u64 changed);
static int fake_wifi_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
			     struct ieee80211_vif *vif, struct ieee80211_sta *sta,
			     struct ieee80211_key_conf *key);
static u64 fake_wifi_get_tsf(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
static void fake_wifi_set_tsf(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u64 tsf);
static void fake_wifi_reset_tsf(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
static int fake_wifi_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				  struct ieee80211_ampdu_params *params);
static int fake_wifi_get_survey(struct ieee80211_hw *hw, int idx, struct survey_info *survey);
static void fake_wifi_rfkill_poll(struct ieee80211_hw *hw);
static void fake_wifi_set_coverage_class(struct ieee80211_hw *hw, s16 coverage_class);
static void fake_wifi_flush(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			    u32 queues, bool drop);
static bool fake_wifi_tx_frames_pending(struct ieee80211_hw *hw);
static int fake_wifi_tx_last_beacon(struct ieee80211_hw *hw);
static void fake_wifi_release_buffered_frames(struct ieee80211_hw *hw,
					      struct ieee80211_sta *sta,
					      u16 tids, int num_frames,
					      enum ieee80211_frame_release_type reason,
					      bool more_data);
static int fake_wifi_get_stats(struct ieee80211_hw *hw, struct ieee80211_low_level_stats *stats);
static int fake_wifi_set_antenna(struct ieee80211_hw *hw, u32 tx_ant, u32 rx_ant);
static int fake_wifi_get_antenna(struct ieee80211_hw *hw, u32 *tx_ant, u32 *rx_ant);
static void fake_wifi_sw_scan_start(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				    const u8 *mac_addr);
static void fake_wifi_sw_scan_complete(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
static int fake_wifi_get_txpower(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				unsigned int link_id, int *dbm);
static int fake_wifi_get_txpower_wrapper(struct ieee80211_hw *hw, struct ieee80211_vif *vif, int *dbm);
static void fake_wifi_wake_tx_queue(struct ieee80211_hw *hw, struct ieee80211_txq *txq);

/*
 * IEEE 802.11 operations structure - This is the interface between
 * our driver and the mac80211 subsystem
 */
static const struct ieee80211_ops fake_wifi_ops = {
	.tx = fake_wifi_tx,
	.start = fake_wifi_start,
	.stop = fake_wifi_stop_wrapper,
	.add_interface = fake_wifi_add_interface,
	.change_interface = fake_wifi_change_interface,
	.remove_interface = fake_wifi_remove_interface,
	.config = fake_wifi_config,
	.configure_filter = fake_wifi_configure_filter,
	.sta_state = fake_wifi_sta_state,
	.sta_notify = fake_wifi_sta_notify,
	.conf_tx = fake_wifi_conf_tx,
	.bss_info_changed = fake_wifi_bss_info_changed,
	.set_key = fake_wifi_set_key,
	.get_tsf = fake_wifi_get_tsf,
	.set_tsf = fake_wifi_set_tsf,
	.reset_tsf = fake_wifi_reset_tsf,
	.ampdu_action = fake_wifi_ampdu_action,
	.get_survey = fake_wifi_get_survey,
	.rfkill_poll = fake_wifi_rfkill_poll,
	.set_coverage_class = fake_wifi_set_coverage_class,
	.flush = fake_wifi_flush,
	.tx_frames_pending = fake_wifi_tx_frames_pending,
	.tx_last_beacon = fake_wifi_tx_last_beacon,
	.release_buffered_frames = fake_wifi_release_buffered_frames,
	.get_stats = fake_wifi_get_stats,
	.set_antenna = fake_wifi_set_antenna,
	.get_antenna = fake_wifi_get_antenna,
	.sw_scan_start = fake_wifi_sw_scan_start,
	.sw_scan_complete = fake_wifi_sw_scan_complete,
	.get_txpower = fake_wifi_get_txpower_wrapper,
	.wake_tx_queue = fake_wifi_wake_tx_queue,

};

/*
 * Helper function to create a fake probe response frame
 * This simulates what a real AP would send when it receives a probe request
 */
static struct sk_buff *fake_wifi_create_probe_response(struct fake_wifi_priv *priv,
						      const u8 *dst_addr)
{
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u8 *pos;
	size_t frame_len;
	
	/* Calculate frame length: 
	 * IEEE 802.11 header + fixed probe response fields + IEs */
	frame_len = sizeof(struct ieee80211_mgmt) + 
		    2 + strlen(FAKE_AP_SSID) +  /* SSID IE */
		    10;  /* Other basic IEs */
	
	skb = dev_alloc_skb(frame_len);
	if (!skb) {
		pr_err("fake_wifi: Failed to allocate probe response skb\n");
		return NULL;
	}
	
	/* Build the probe response frame */
	mgmt = (struct ieee80211_mgmt *)skb_put(skb, sizeof(struct ieee80211_mgmt));
	memset(mgmt, 0, sizeof(struct ieee80211_mgmt));
	
	/* Frame control: probe response */
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | 
					  IEEE80211_STYPE_PROBE_RESP);
	
	/* Addresses */
	memcpy(mgmt->da, dst_addr, ETH_ALEN);           /* Destination: requester */
	memcpy(mgmt->sa, FAKE_AP_BSSID, ETH_ALEN);      /* Source: our fake AP */
	memcpy(mgmt->bssid, FAKE_AP_BSSID, ETH_ALEN);   /* BSSID: our fake AP */
	/* Sequence number (fake) */
	mgmt->seq_ctrl = cpu_to_le16(0x1234);
	
	/* Fixed probe response fields */
	mgmt->u.probe_resp.timestamp = cpu_to_le64(jiffies);
	mgmt->u.probe_resp.beacon_int = cpu_to_le16(100);  /* 100 TU beacon interval */
	mgmt->u.probe_resp.capab_info = cpu_to_le16(0x0401);  /* ESS + Short preamble */
	
	/* Add Information Elements */
	pos = skb_put(skb, 2 + strlen(FAKE_AP_SSID));
	
	/* SSID IE */
	*pos++ = WLAN_EID_SSID;
	*pos++ = strlen(FAKE_AP_SSID);
	memcpy(pos, FAKE_AP_SSID, strlen(FAKE_AP_SSID));
	
	pr_info("fake_wifi: Created probe response for %pM, SSID: %s\n", 
		dst_addr, FAKE_AP_SSID);
	
	return skb;
}

/*
 * Work function to handle probe response generation
 * This runs in process context, allowing us to safely call mac80211 functions
 */
static void fake_wifi_probe_response_work(struct work_struct *work)
{
	struct fake_wifi_priv *priv;
	struct sk_buff *probe_req, *probe_resp;
	struct ieee80211_mgmt *mgmt;
	struct ieee80211_rx_status rx_status;
	
	if (!work) {
		pr_err("fake_wifi: work is NULL in probe_response_work\n");
		return;
	}
	
	priv = container_of(work, struct fake_wifi_priv, probe_response_work);
	if (!priv) {
		pr_err("fake_wifi: priv is NULL in probe_response_work\n");
		return;
	}
	
	if (!priv->hw) {
		pr_err("fake_wifi: hw is NULL in probe_response_work\n");
		return;
	}
	
	while ((probe_req = skb_dequeue(&priv->probe_queue)) != NULL) {
		if (!probe_req->data) {
			pr_err("fake_wifi: probe_req->data is NULL\n");
			dev_kfree_skb(probe_req);
			continue;
		}
		
		mgmt = (struct ieee80211_mgmt *)probe_req->data;
		
		pr_info("fake_wifi: Processing probe request from %pM\n", mgmt->sa);
		
		/* Create fake probe response */
		probe_resp = fake_wifi_create_probe_response(priv, mgmt->sa);
		if (!probe_resp) {
			dev_kfree_skb(probe_req);
			continue;
		}
		
		/* Prepare rx_status for the fake probe response */
		memset(&rx_status, 0, sizeof(rx_status));
		rx_status.freq = 2437;  /* Channel 6 - 2437 MHz */
		rx_status.band = NL80211_BAND_2GHZ;
		rx_status.signal = -30;  /* Fake signal strength */
		rx_status.antenna = 1;
		rx_status.flag = RX_FLAG_DECRYPTED;  /* No encryption */
		
		/* Copy rx_status to skb */
		memcpy(IEEE80211_SKB_RXCB(probe_resp), &rx_status, sizeof(rx_status));
		
		/* Inject the fake probe response into mac80211 
		 * This makes it appear as if we received it from the air */
		ieee80211_rx(priv->hw, probe_resp);
		
		priv->probe_responses_sent++;
		pr_info("fake_wifi: Sent fake probe response #%u to %pM\n",
			priv->probe_responses_sent, mgmt->sa);
		
		dev_kfree_skb(probe_req);
	}
}

/*
 * Parse and handle a potential probe request frame
 * Called from the TX path when frames are being transmitted
 */
static void fake_wifi_handle_probe_request(struct fake_wifi_priv *priv,
					   struct sk_buff *skb)
{
	struct ieee80211_mgmt *mgmt;
	struct sk_buff *probe_copy;
	
	if (!priv) {
		pr_err("fake_wifi: priv is NULL in handle_probe_request\n");
		return;
	}
	
	if (!skb || !skb->data) {
		pr_err("fake_wifi: skb or skb->data is NULL in handle_probe_request\n");
		return;
	}
	
	if (skb->len < sizeof(struct ieee80211_mgmt))
		return;
	
	mgmt = (struct ieee80211_mgmt *)skb->data;
	
	/* Check if this is a probe request */
	if ((mgmt->frame_control & cpu_to_le16(IEEE80211_FCTL_FTYPE)) != 
	    cpu_to_le16(IEEE80211_FTYPE_MGMT))
		return;
	
	if ((mgmt->frame_control & cpu_to_le16(IEEE80211_FCTL_STYPE)) != 
	    cpu_to_le16(IEEE80211_STYPE_PROBE_REQ))
		return;
	
	priv->probe_requests_received++;
	pr_info("fake_wifi: *** PROBE REQUEST #%u INTERCEPTED ***\n", 
		priv->probe_requests_received);
	pr_info("fake_wifi: From: %pM, To: %pM, BSSID: %pM\n", 
		mgmt->sa, mgmt->da, mgmt->bssid);
	
	/* Queue probe request for response generation */
	probe_copy = skb_copy(skb, GFP_ATOMIC);
	if (probe_copy) {
		spin_lock(&priv->probe_lock);
		skb_queue_tail(&priv->probe_queue, probe_copy);
		spin_unlock(&priv->probe_lock);
		
		/* Schedule work to generate probe response */
		schedule_work(&priv->probe_response_work);
	}
}
/*
 * Start the fake hardware
 * Called when the interface is brought up (ifconfig wlan0 up)
 */
static int fake_wifi_start(struct ieee80211_hw *hw)
{
	struct fake_wifi_priv *priv;
	
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in start\n");
		return -EINVAL;
	}
	
	priv = hw->priv;
	pr_info("fake_wifi: hw->priv = %p\n", priv);
	if (!priv) {
		pr_err("fake_wifi: priv is NULL in start\n");
		return -EINVAL;
	}
	
	pr_info("fake_wifi: *** STARTING FAKE HARDWARE ***\n");
	
	/* Initialize fake hardware state */
	pr_info("fake_wifi: Setting priv->hw_started = true\n");
	priv->hw_started = true;
	pr_info("fake_wifi: Setting priv->current_channel = %d\n", FAKE_WIFI_CHANNEL_2GHZ);
	priv->current_channel = FAKE_WIFI_CHANNEL_2GHZ;
	
	/* Reset statistics */
	priv->probe_requests_received = 0;
	priv->probe_responses_sent = 0;
	
	pr_info("fake_wifi: Fake hardware started successfully\n");
	return 0;
}

/*
 * Stop the fake hardware
 * Called when the interface is brought down (ifconfig wlan0 down)
 */
static void fake_wifi_stop(struct ieee80211_hw *hw, bool suspend)
{
	struct fake_wifi_priv *priv;
	
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in stop\n");
		return;
	}
	
	priv = hw->priv;
	pr_info("fake_wifi: hw->priv = %p\n", priv);
	if (!priv) {
		pr_err("fake_wifi: priv is NULL in stop\n");
		return;
	}
	
	pr_info("fake_wifi: *** STOPPING FAKE HARDWARE *** (suspend=%d)\n", suspend);
	
	/* Stop the hardware */
	pr_info("fake_wifi: Setting priv->hw_started = false\n");
	priv->hw_started = false;
	
	/* Cancel any pending work */
	cancel_work_sync(&priv->probe_response_work);
	
	/* Clear probe queue */
	skb_queue_purge(&priv->probe_queue);
	
	pr_info("fake_wifi: Statistics: %u probe requests, %u responses sent\n",
		priv->probe_requests_received, priv->probe_responses_sent);
	pr_info("fake_wifi: Fake hardware stopped\n");
}

/*
 * Transmit function - This is where we intercept frames from mac80211
 * In a real driver, this would program the hardware to transmit
 * For us, this is where we detect probe requests
 */
static void fake_wifi_tx(struct ieee80211_hw *hw,
			 struct ieee80211_tx_control *control,
			 struct sk_buff *skb)
{
       struct fake_wifi_priv *priv;
       struct ieee80211_tx_info *info;
       struct ieee80211_hdr *hdr;
       u16 fc, ftype, stype;

       if (!hw) {
	       pr_err("fake_wifi: hw is NULL in tx\n");
	       if (skb)
		       dev_kfree_skb(skb);
	       return;
       }

       if (!skb) {
	       pr_err("fake_wifi: skb is NULL in tx\n");
	       return;
       }

       priv = hw->priv;
       pr_info("fake_wifi: tx: hw->priv = %p\n", priv);
       if (!priv) {
	       pr_err("fake_wifi: priv is NULL in tx\n");
	       dev_kfree_skb(skb);
	       return;
       }

       info = IEEE80211_SKB_CB(skb);
       pr_info("fake_wifi: tx: IEEE80211_SKB_CB(skb) = %p\n", info);
       if (!info) {
	       pr_err("fake_wifi: tx_info is NULL in tx\n");
	       dev_kfree_skb(skb);
	       return;
       }

       pr_info("fake_wifi: tx: Checking priv->hw_started = %d\n", priv->hw_started);
       if (!priv->hw_started) {
	       dev_kfree_skb(skb);
	       return;
       }

       pr_debug("fake_wifi: TX frame of length %u\n", skb->len);

       /* Log all outgoing frames (including data frames) */
       if (skb->len >= 2) {
	       hdr = (struct ieee80211_hdr *)skb->data;
	       fc = le16_to_cpu(hdr->frame_control);
	       ftype = fc & IEEE80211_FCTL_FTYPE;
	       stype = fc & IEEE80211_FCTL_STYPE;

	       pr_info("fake_wifi: TX frame: type=0x%x stype=0x%x len=%u DA=%pM SA=%pM BSSID=%pM\n",
		       ftype, stype, skb->len, hdr->addr1, hdr->addr2, hdr->addr3);
       } else {
	       pr_info("fake_wifi: TX frame: too short to parse header, len=%u\n", skb->len);
       }

       /* Check if this is a probe request that we should respond to */
       fake_wifi_handle_probe_request(priv, skb);

       /* Simulate successful transmission */
       info->flags |= IEEE80211_TX_STAT_ACK;

       /* Report transmission completion to mac80211 */
       ieee80211_tx_status_ni(hw, skb);
}

/*
 * Configuration change handler
 * Called when channel, power, etc. are changed
 */
static int fake_wifi_config(struct ieee80211_hw *hw, u32 changed)
{
	struct fake_wifi_priv *priv;
	struct ieee80211_conf *conf;
	
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in config\n");
		return -EINVAL;
	}
	
	priv = hw->priv;
	pr_info("fake_wifi: config: hw->priv = %p\n", priv);
	if (!priv) {
		pr_err("fake_wifi: priv is NULL in config\n");
		return -EINVAL;
	}
	
	conf = &hw->conf;
	pr_info("fake_wifi: config: &hw->conf = %p\n", conf);
	if (!conf) {
		pr_err("fake_wifi: conf is NULL in config\n");
		return -EINVAL;
	}
	
	if (changed & IEEE80211_CONF_CHANGE_CHANNEL) {
		pr_info("fake_wifi: config: conf->chandef.chan = %p\n", conf->chandef.chan);
		if (conf->chandef.chan) {
			pr_info("fake_wifi: config: Setting priv->current_channel = conf->chandef.chan->hw_value = %d\n", conf->chandef.chan->hw_value);
			priv->current_channel = conf->chandef.chan->hw_value;
			pr_info("fake_wifi: Channel changed to %u (%u MHz)\n",
				priv->current_channel, conf->chandef.chan->center_freq);
		} else {
			pr_err("fake_wifi: Channel is NULL in config\n");
		}
	}
	
	if (changed & IEEE80211_CONF_CHANGE_POWER) {
		pr_info("fake_wifi: TX power changed to %d dBm\n", conf->power_level);
	}
	
	return 0;
}

/*
 * Filter configuration
 * Called when the frame filtering requirements change
 */
static void fake_wifi_configure_filter(struct ieee80211_hw *hw,
				       unsigned int changed_flags,
				       unsigned int *total_flags,
				       u64 multicast)
{
	pr_debug("fake_wifi: Filter configuration changed: 0x%x\n", *total_flags);
	
	/* Accept all frames for simplicity */
	*total_flags = FIF_ALLMULTI | FIF_OTHER_BSS;
}

/*
 * Add interface - Called when an interface is created (e.g., wlan0)
 */
static int fake_wifi_add_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct fake_wifi_priv *priv;
	
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in add_interface\n");
		return -EINVAL;
	}
	
	if (!vif) {
		pr_err("fake_wifi: vif is NULL in add_interface\n");
		return -EINVAL;
	}
	
	priv = hw->priv;
	pr_info("fake_wifi: add_interface: hw->priv = %p\n", priv);
	if (!priv) {
		pr_err("fake_wifi: priv is NULL in add_interface\n");
		return -EINVAL;
	}
	
	pr_info("fake_wifi: add_interface: vif->type = %d, vif->addr = %pM\n", vif->type, vif->addr);
	pr_info("fake_wifi: Setting priv->vif = %p\n", vif);
	priv->vif = vif;
	return 0;
}

/*
 * Remove interface - Called when an interface is destroyed
 */
static void fake_wifi_remove_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct fake_wifi_priv *priv;
	
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in remove_interface\n");
		return;
	}
	
	if (!vif) {
		pr_err("fake_wifi: vif is NULL in remove_interface\n");
		return;
	}
	
	priv = hw->priv;
	if (!priv) {
		pr_err("fake_wifi: priv is NULL in remove_interface\n");
		return;
	}
	
	pr_info("fake_wifi: Removing interface (addr: %pM)\n", vif->addr);
	priv->vif = NULL;
}

/*
 * Change interface type
 */
static int fake_wifi_change_interface(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				      enum nl80211_iftype new_type, bool p2p)
{
	pr_info("fake_wifi: Changing interface to type %d\n", new_type);
	return 0;
}

/*
 * Station state change
 */
static int fake_wifi_sta_state(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			       struct ieee80211_sta *sta, enum ieee80211_sta_state old_state,
			       enum ieee80211_sta_state new_state)
{
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in sta_state\n");
		return -EINVAL;
	}
	
	if (!vif) {
		pr_err("fake_wifi: vif is NULL in sta_state\n");
		return -EINVAL;
	}
	
	if (!sta) {
		pr_err("fake_wifi: sta is NULL in sta_state\n");
		return -EINVAL;
	}
	
	pr_info("fake_wifi: Station %pM state change %d->%d\n", sta->addr, old_state, new_state);
	return 0;
}

/*
 * Station notification
 */
static void fake_wifi_sta_notify(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				 enum sta_notify_cmd cmd, struct ieee80211_sta *sta)
{
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in sta_notify\n");
		return;
	}
	
	if (!vif) {
		pr_err("fake_wifi: vif is NULL in sta_notify\n");
		return;
	}
	
	if (!sta) {
		pr_err("fake_wifi: sta is NULL in sta_notify\n");
		return;
	}
	
	pr_info("fake_wifi: Station notify cmd %d for %pM\n", cmd, sta->addr);
}

/*
 * Configure TX queues
 */
static int fake_wifi_conf_tx(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			     unsigned int ac, u16 queue,
			     const struct ieee80211_tx_queue_params *params)
{
	pr_info("fake_wifi: Configure TX queue %d (ac=%u)\n", queue, ac);
	return 0;
}

/*
 * BSS info changed
 */
static void fake_wifi_bss_info_changed(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				       struct ieee80211_bss_conf *info, u64 changed)
{
	pr_info("fake_wifi: BSS info changed (flags: 0x%llx)\n", changed);
}

/*
 * Set encryption key
 */
static int fake_wifi_set_key(struct ieee80211_hw *hw, enum set_key_cmd cmd,
			     struct ieee80211_vif *vif, struct ieee80211_sta *sta,
			     struct ieee80211_key_conf *key)
{
	pr_info("fake_wifi: Set key command %d\n", cmd);
	return 0;
}

/*
 * Get TSF timer
 */
static u64 fake_wifi_get_tsf(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	return jiffies;
}

/*
 * Set TSF timer
 */
static void fake_wifi_set_tsf(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u64 tsf)
{
	pr_info("fake_wifi: Set TSF to %llu\n", tsf);
}

/*
 * Reset TSF timer
 */
static void fake_wifi_reset_tsf(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	pr_info("fake_wifi: Reset TSF\n");
}

/*
 * AMPDU action
 */
static int fake_wifi_ampdu_action(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				  struct ieee80211_ampdu_params *params)
{
	pr_info("fake_wifi: AMPDU action %d\n", params->action);
	return 0;
}

/*
 * Get survey data
 */
static int fake_wifi_get_survey(struct ieee80211_hw *hw, int idx, struct survey_info *survey)
{
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in get_survey\n");
		return -EINVAL;
	}
	
	if (!survey) {
		pr_err("fake_wifi: survey is NULL in get_survey\n");
		return -EINVAL;
	}
	
	pr_info("fake_wifi: get_survey: hw->wiphy = %p\n", hw->wiphy);
	if (!hw->wiphy) {
		pr_err("fake_wifi: wiphy is NULL in get_survey\n");
		return -EINVAL;
	}
	
	if (idx != 0)
		return -ENOENT;
	
	/* Use the already allocated channel from our band structure */
	pr_info("fake_wifi: get_survey: hw->wiphy->bands[NL80211_BAND_2GHZ] = %p\n", hw->wiphy->bands[NL80211_BAND_2GHZ]);
	if (hw->wiphy->bands[NL80211_BAND_2GHZ] && 
	    hw->wiphy->bands[NL80211_BAND_2GHZ]->channels) {
		pr_info("fake_wifi: get_survey: Setting survey->channel = %p\n", &hw->wiphy->bands[NL80211_BAND_2GHZ]->channels[0]);
		survey->channel = &hw->wiphy->bands[NL80211_BAND_2GHZ]->channels[0];
	} else {
		return -ENOENT;
	}
	
	survey->filled = SURVEY_INFO_NOISE_DBM;
	survey->noise = -95;
	
	return 0;
}

/*
 * RF-kill poll
 */
static void fake_wifi_rfkill_poll(struct ieee80211_hw *hw)
{
	/* RF is always enabled in fake driver */
}

/*
 * Set coverage class
 */
static void fake_wifi_set_coverage_class(struct ieee80211_hw *hw, s16 coverage_class)
{
	pr_info("fake_wifi: Set coverage class %d\n", coverage_class);
}

/*
 * Flush queues
 */
static void fake_wifi_flush(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			    u32 queues, bool drop)
{
	pr_info("fake_wifi: Flush queues 0x%x (drop=%d)\n", queues, drop);
}

/*
 * Check if TX frames are pending
 */
static bool fake_wifi_tx_frames_pending(struct ieee80211_hw *hw)
{
	return false; /* No frames pending in fake driver */
}

/*
 * TX last beacon
 */
static int fake_wifi_tx_last_beacon(struct ieee80211_hw *hw)
{
	return 1; /* Always say we transmitted last beacon */
}

/*
 * Release buffered frames
 */
static void fake_wifi_release_buffered_frames(struct ieee80211_hw *hw,
					      struct ieee80211_sta *sta,
					      u16 tids, int num_frames,
					      enum ieee80211_frame_release_type reason,
					      bool more_data)
{
	pr_info("fake_wifi: Release buffered frames for %pM\n", sta->addr);
}

/*
 * Get low-level stats
 */
static int fake_wifi_get_stats(struct ieee80211_hw *hw, struct ieee80211_low_level_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	return 0;
}

/*
 * Set antenna configuration
 */
static int fake_wifi_set_antenna(struct ieee80211_hw *hw, u32 tx_ant, u32 rx_ant)
{
	pr_info("fake_wifi: Set antenna TX=0x%x RX=0x%x\n", tx_ant, rx_ant);
	return 0;
}

/*
 * Get antenna configuration
 */
static int fake_wifi_get_antenna(struct ieee80211_hw *hw, u32 *tx_ant, u32 *rx_ant)
{
	*tx_ant = 1;
	*rx_ant = 1;
	return 0;
}

/*
 * Software scan start
 */
static void fake_wifi_sw_scan_start(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				    const u8 *mac_addr)
{
	pr_info("fake_wifi: Software scan start\n");
}

/*
 * Software scan complete
 */
static void fake_wifi_sw_scan_complete(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
    struct ieee80211_channel *chan;
	struct cfg80211_bss *bss;
	struct ieee80211_supported_band *band;
	u8 buf[256];
	int pos = 0;
	int ssid_len = strlen(FAKE_AP_SSID);
	int i;

       pr_info("fake_wifi: Software scan complete\n");

       if (!hw || !hw->wiphy) {
	       pr_err("fake_wifi: hw or wiphy is NULL in sw_scan_complete\n");
	       return;
       }

       band = hw->wiphy->bands[NL80211_BAND_2GHZ];
       if (!band) {
	       pr_err("fake_wifi: band is NULL in sw_scan_complete\n");
	       return;
       }
       chan = &band->channels[0];

       // Build Information Elements (IEs)
       // SSID
       buf[pos++] = WLAN_EID_SSID;
       buf[pos++] = ssid_len;
       memcpy(&buf[pos], FAKE_AP_SSID, ssid_len);
       pos += ssid_len;

       // Supported Rates
       buf[pos++] = WLAN_EID_SUPP_RATES;
       int num_rates = band->n_bitrates > 8 ? 8 : band->n_bitrates;
       buf[pos++] = num_rates;
       for (i = 0; i < num_rates; i++)
	       buf[pos++] = (u8)(band->bitrates[i].bitrate / 5);

       // Extended Supported Rates (if any)
       if (band->n_bitrates > 8) {
	       buf[pos++] = WLAN_EID_EXT_SUPP_RATES;
	       buf[pos++] = band->n_bitrates - 8;
	       for (i = 8; i < band->n_bitrates; i++)
		       buf[pos++] = (u8)(band->bitrates[i].bitrate / 5);
       }

       // Capabilities: ESS, short preamble
       u16 capab_info = WLAN_CAPABILITY_ESS | WLAN_CAPABILITY_SHORT_PREAMBLE;

       // Fake BSSID
       u8 bssid[ETH_ALEN];
       memcpy(bssid, FAKE_AP_BSSID, ETH_ALEN);

       // Inform BSS to cfg80211 (modern kernel signature)
       bss = cfg80211_inform_bss(
	       hw->wiphy,
	       chan,
	       CFG80211_BSS_FTYPE_UNKNOWN,
	       bssid,
	       0, // timestamp
	       capab_info,
	       100, // beacon interval
	       buf,
	       pos,
	       -30, // signal (dBm)
	       GFP_KERNEL
       );
       if (bss) {
	       cfg80211_put_bss(hw->wiphy, bss);
	       pr_info("fake_wifi: Fake AP pushed to scan results: SSID=%s, BSSID=%pM\n", FAKE_AP_SSID, bssid);
       } else {
	       pr_err("fake_wifi: Failed to inform fake AP BSS in scan complete\n");
       }
}

/*
 * Get TX power
 */
static int fake_wifi_get_txpower(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
				 unsigned int link_id, int *dbm)
{
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in get_txpower\n");
		return -EINVAL;
	}
	
	if (!dbm) {
		pr_err("fake_wifi: dbm is NULL in get_txpower\n");
		return -EINVAL;
	}
	
	*dbm = FAKE_WIFI_MAX_TX_POWER;
	return 0;
}

/*
 * Wake TX queue
 */
static void fake_wifi_wake_tx_queue(struct ieee80211_hw *hw, struct ieee80211_txq *txq)
{
	pr_debug("fake_wifi: Wake TX queue\n");
}

/*
 * Initialize the fake hardware capabilities and register with mac80211
 */
static int fake_wifi_init_hw(struct fake_wifi_priv *priv)
{
	struct ieee80211_hw *hw;
	struct ieee80211_supported_band *band;
	struct ieee80211_channel *channel;
	struct ieee80211_rate *rate;
	int ret;
	
	if (!priv) {
		pr_err("fake_wifi: priv is NULL in init_hw\n");
		return -EINVAL;
	}
	
	hw = priv->hw;
	pr_info("fake_wifi: init_hw: priv->hw = %p\n", hw);
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in init_hw\n");
		return -EINVAL;
	}
	
	pr_info("fake_wifi: init_hw: hw->wiphy = %p\n", hw->wiphy);
	if (!hw->wiphy) {
		pr_err("fake_wifi: wiphy is NULL in init_hw\n");
		return -EINVAL;
	}
	
	pr_info("fake_wifi: Initializing fake hardware capabilities\n");
	
	/* Allocate memory for band structure */
	band = kzalloc(sizeof(*band), GFP_KERNEL);
	if (!band) {
		pr_err("fake_wifi: Failed to allocate band structure\n");
		return -ENOMEM;
	}
	
	/* Allocate memory for channel structure */
	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel) {
		pr_err("fake_wifi: Failed to allocate channel structure\n");
		kfree(band);
		return -ENOMEM;
	}
	
	/* Allocate memory for rate array */
	rate = kzalloc(sizeof(struct ieee80211_rate) * FAKE_WIFI_NUM_RATES, GFP_KERNEL);
	if (!rate) {
		pr_err("fake_wifi: Failed to allocate rate array\n");
		kfree(channel);
		kfree(band);
		return -ENOMEM;
	}
	
	/* Copy the comprehensive rate table */
	memcpy(rate, fake_wifi_rates, sizeof(struct ieee80211_rate) * FAKE_WIFI_NUM_RATES);
	pr_info("fake_wifi: init_hw: Copied %d rates from fake_wifi_rates\n", FAKE_WIFI_NUM_RATES);
	
	/* Initialize channel structure */
	pr_info("fake_wifi: init_hw: Setting channel->band = %d\n", NL80211_BAND_2GHZ);
	channel->band = NL80211_BAND_2GHZ;
	pr_info("fake_wifi: init_hw: Setting channel->center_freq = 2437\n");
	channel->center_freq = 2437;  /* Channel 6 */
	pr_info("fake_wifi: init_hw: Setting channel->hw_value = 6\n");
	channel->hw_value = 6;
	pr_info("fake_wifi: init_hw: Setting channel->max_power = %d\n", FAKE_WIFI_MAX_TX_POWER);
	channel->max_power = FAKE_WIFI_MAX_TX_POWER;
	pr_info("fake_wifi: init_hw: Setting channel->flags = 0\n");
	channel->flags = 0;
	
	/* Initialize band structure with comprehensive rate support */
	pr_info("fake_wifi: init_hw: Setting band->band = %d\n", NL80211_BAND_2GHZ);
	band->band = NL80211_BAND_2GHZ;
	pr_info("fake_wifi: init_hw: Setting band->n_channels = 1\n");
	band->n_channels = 1;
	pr_info("fake_wifi: init_hw: Setting band->channels = %p\n", channel);
	band->channels = channel;
	pr_info("fake_wifi: init_hw: Setting band->n_bitrates = %d\n", FAKE_WIFI_NUM_RATES);
	band->n_bitrates = FAKE_WIFI_NUM_RATES;
	pr_info("fake_wifi: init_hw: Setting band->bitrates = %p\n", rate);
	band->bitrates = rate;
	pr_info("fake_wifi: init_hw: Rate array configured with %d rates (1-54 Mbps)\n", FAKE_WIFI_NUM_RATES);
	
	/* Set hardware capabilities */
	pr_info("fake_wifi: init_hw: Setting hardware capabilities...\n");
	ieee80211_hw_set(hw, SIGNAL_DBM);
	ieee80211_hw_set(hw, SUPPORTS_PS);
	ieee80211_hw_set(hw, AMPDU_AGGREGATION);

	pr_info("fake_wifi: init_hw: Hardware capabilities set\n");
	
	/* Set supported interface modes */
	hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
				    BIT(NL80211_IFTYPE_AP) |
				    BIT(NL80211_IFTYPE_MONITOR);
	
	/* Set wiphy name and driver info */
	pr_info("fake_wifi: init_hw: Setting wiphy driver name...\n");
	strscpy(hw->wiphy->fw_version, FAKE_WIFI_VERSION, sizeof(hw->wiphy->fw_version));
	hw->wiphy->hw_version = 1;
	
	/* Set driver name for proper cfg80211 integration */
	if (hw->wiphy->dev.parent && hw->wiphy->dev.parent->driver) {
		pr_info("fake_wifi: init_hw: Parent driver already set\n");
	} else {
		pr_info("fake_wifi: init_hw: Setting up driver info for cfg80211\n");
	}
	
	pr_info("fake_wifi: init_hw: Driver info configured\n");
	
	/* Set supported bands and channels */
	pr_info("fake_wifi: init_hw: Setting hw->wiphy->bands[NL80211_BAND_2GHZ] = %p\n", band);
	hw->wiphy->bands[NL80211_BAND_2GHZ] = band;
	
	/* Set hardware address (fake MAC) */
	SET_IEEE80211_PERM_ADDR(hw, FAKE_AP_BSSID);
	
	/* Set additional wiphy parameters */
	pr_info("fake_wifi: init_hw: Setting additional wiphy parameters...\n");
	hw->wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
	hw->wiphy->max_scan_ssids = 1;
	hw->wiphy->max_scan_ie_len = 256;
	pr_info("fake_wifi: init_hw: Additional wiphy parameters set\n");
	
	/* Set hardware limits */
	pr_info("fake_wifi: init_hw: Setting hardware limits...\n");
	hw->max_rates = FAKE_WIFI_NUM_RATES;
	hw->max_rate_tries = 3;
	hw->extra_tx_headroom = 0;
	hw->queues = 1;
	pr_info("fake_wifi: init_hw: Hardware limits set (max_rates=%d)\n", FAKE_WIFI_NUM_RATES);
	
	/* Register with mac80211 */
	ret = ieee80211_register_hw(hw);
	if (ret) {
		pr_err("fake_wifi: Failed to register hardware: %d\n", ret);
		kfree(rate);
		kfree(channel);
		kfree(band);
		return ret;
	}
	
	pr_info("fake_wifi: Hardware registered successfully with mac80211\n");
	pr_info("fake_wifi: Fake AP ready - SSID: %s, BSSID: %pM\n", 
		FAKE_AP_SSID, FAKE_AP_BSSID);
	
	return 0;
}

/*
 * Module initialization
 */

/* Fake platform device for proper driver integration */
static struct platform_device *fake_wifi_pdev = NULL;
static struct device_driver fake_wifi_driver = {
	.name = FAKE_WIFI_DRIVER_NAME,
};

static int __init fake_wifi_init(void)
{
	struct ieee80211_hw *hw;
	struct fake_wifi_priv *priv;
	int ret;
	
	pr_info("fake_wifi: Loading Fake Wi-Fi Driver v%s\n", FAKE_WIFI_VERSION);
	
	/* Create a fake platform device for proper driver integration */
	fake_wifi_pdev = platform_device_register_simple(FAKE_WIFI_DRIVER_NAME, -1, NULL, 0);
	if (IS_ERR(fake_wifi_pdev)) {
		pr_err("fake_wifi: Failed to register platform device\n");
		return PTR_ERR(fake_wifi_pdev);
	}
	
	/* Set up the driver structure */
	fake_wifi_pdev->dev.driver = &fake_wifi_driver;
	
	/* Allocate hardware structure with private data */
	hw = ieee80211_alloc_hw(sizeof(struct fake_wifi_priv), &fake_wifi_ops);
	if (!hw) {
		pr_err("fake_wifi: Failed to allocate hardware structure\n");
		platform_device_unregister(fake_wifi_pdev);
		return -ENOMEM;
	}
	
	/* Set the parent device for proper cfg80211 integration */
	SET_IEEE80211_DEV(hw, &fake_wifi_pdev->dev);
	
	/* Initialize private data */
	priv = hw->priv;
	pr_info("fake_wifi: init: hw->priv = %p\n", priv);
	if (!priv) {
		pr_err("fake_wifi: Failed to get private data\n");
		ieee80211_free_hw(hw);
		return -ENOMEM;
	}
	
	memset(priv, 0, sizeof(*priv));
	pr_info("fake_wifi: init: Setting priv->hw = %p\n", hw);
	priv->hw = hw;
	pr_info("fake_wifi: init: Setting priv->hw_started = false\n");
	priv->hw_started = false;
	pr_info("fake_wifi: init: Setting priv->vif = NULL\n");
	priv->vif = NULL;
	pr_info("fake_wifi: init: Setting priv->current_channel = 6\n");
	priv->current_channel = 6;
	pr_info("fake_wifi: init: Setting priv->probe_requests_received = 0\n");
	priv->probe_requests_received = 0;
	pr_info("fake_wifi: init: Setting priv->probe_responses_sent = 0\n");
	priv->probe_responses_sent = 0;
	
	/* Initialize probe handling */
	INIT_WORK(&priv->probe_response_work, fake_wifi_probe_response_work);
 	skb_queue_head_init(&priv->probe_queue);
	spin_lock_init(&priv->probe_lock);
	
	/* Initialize and register hardware */
	ret = fake_wifi_init_hw(priv);
	if (ret) {
		ieee80211_free_hw(hw);
		platform_device_unregister(fake_wifi_pdev);
		return ret;
	}
	
	/* Store hardware pointer globally for cleanup */
	global_hw = hw;
	
	pr_info("fake_wifi: Driver loaded successfully\n");
	pr_info("fake_wifi: Use 'iw dev wlan0 scan trigger' to test probe requests\n");
	
	return 0;
}

/*
 * Module cleanup
 */
static void __exit fake_wifi_exit(void)
{
	pr_info("fake_wifi: Unloading Fake Wi-Fi Driver\n");
	
       pr_info("fake_wifi: exit: global_hw = %p\n", global_hw);
       if (global_hw) {
	       pr_info("fake_wifi: Unregistering hardware...\n");
	       ieee80211_unregister_hw(global_hw);

	       /* Free allocated band structures after unregistering, before free_hw */
	       pr_info("fake_wifi: exit: global_hw->wiphy = %p\n", global_hw->wiphy);
	       if (global_hw->wiphy && global_hw->wiphy->bands[NL80211_BAND_2GHZ]) {
		       struct ieee80211_supported_band *band = global_hw->wiphy->bands[NL80211_BAND_2GHZ];
		       pr_info("fake_wifi: exit: band = %p\n", band);
		       if (band) {
			       pr_info("fake_wifi: exit: band->bitrates = %p\n", band->bitrates);
			       if (band->bitrates)
				       kfree(band->bitrates);
			       pr_info("fake_wifi: exit: band->channels = %p\n", band->channels);
			       if (band->channels)
				       kfree(band->channels);
			       kfree(band);
			       global_hw->wiphy->bands[NL80211_BAND_2GHZ] = NULL;
		       }
	       }

	       ieee80211_free_hw(global_hw);
	       global_hw = NULL;
	       pr_info("fake_wifi: Hardware unregistered and freed\n");
       }
	
	/* Clean up platform device */
	if (fake_wifi_pdev) {
		platform_device_unregister(fake_wifi_pdev);
		fake_wifi_pdev = NULL;
		pr_info("fake_wifi: Platform device cleaned up\n");
	}
	
	pr_info("fake_wifi: Driver unloaded\n");
}

module_init(fake_wifi_init);
module_exit(fake_wifi_exit);

MODULE_AUTHOR("FakeWiFi Developer");
MODULE_DESCRIPTION("Fake Wi-Fi Driver for Testing - SoftMAC Implementation");
MODULE_LICENSE("GPL");
MODULE_VERSION(FAKE_WIFI_VERSION);

/*
 * Wrapper for ieee80211_ops .stop (no suspend argument)
 */
static void fake_wifi_stop_wrapper(struct ieee80211_hw *hw) {
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in stop_wrapper\n");
		return;
	}
	fake_wifi_stop(hw, false);
}

/*
 * Wrapper for ieee80211_ops .get_txpower (no link_id argument)
 */
static int fake_wifi_get_txpower_wrapper(struct ieee80211_hw *hw, struct ieee80211_vif *vif, int *dbm) {
	if (!hw) {
		pr_err("fake_wifi: hw is NULL in get_txpower_wrapper\n");
		return -EINVAL;
	}
	if (!dbm) {
		pr_err("fake_wifi: dbm is NULL in get_txpower_wrapper\n");
		return -EINVAL;
	}
	return fake_wifi_get_txpower(hw, vif, 0, dbm);
}
