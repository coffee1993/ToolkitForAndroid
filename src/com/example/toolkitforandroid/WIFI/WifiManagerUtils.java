package com.example.toolkitforandroid.WIFI;

/**
 * wifi Utils 管理Wifi wifi等基本使用
 * @author zy
 *
 */

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import android.R.integer;
import android.annotation.SuppressLint;
import android.app.LocalActivityManager;
import android.content.Context;
import android.content.res.Configuration;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.NetworkInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.nfc.Tag;
import android.text.GetChars;

/**
 * wifimanager --> wifiinfo dhcpinfo ConnectManager --> networkinfo
 * 
 * ConnectManager 与 Wifimanager的关系
 * 
 * @author zhangyi
 * 
 */
public class WifiManagerUtils {

	private static final String TAG_STRING = "NearChat";
	private WifiManager wifimanager;
	private WifiInfo wifiInfo;
	private DhcpInfo dhcpInfo;
	private NetworkInfo networkInfo;
	private StringBuffer buffer;

	private List<ScanResult> scanResults = null; // 扫描的wifi结果集
	private List<WifiConfiguration> wifiConfigurations = null;
	private ConnectivityManager connectivityManager;

	private static WifiManagerUtils managerUtils = null;

	// 需要打开锁
	private WifiManager.WifiLock mWifiLock;

	public static enum WifiChiperType {
		WIFICIPHER_WEP, WIFICIPHER_WPA, WIFICIPHER_NOPASS
	}

	private WifiManagerUtils(Context pContext) {
		wifimanager = (WifiManager) pContext
				.getSystemService(Context.WIFI_SERVICE); // 这行代码写在这里好还是写在字段那里好

		wifiInfo = wifimanager.getConnectionInfo(); // 获取当前连接的wifi网络
		dhcpInfo = wifimanager.getDhcpInfo();

		// 问题出在这里 networkInfo是什么网络信息
		/*
		 * networkInfo = ((ConnectivityManager) pContext
		 * .getSystemService(Context
		 * .CAPTIONING_SERVICE)).getNetworkInfo(ConnectivityManager.TYPE_WIFI);
		 *//*
			 * networkInfo = connectivityManager
			 * .getNetworkInfo(ConnectivityManager.TYPE_WIFI); //wifi类型的网络连接
			 */
		wifiConfigurations = new ArrayList<WifiConfiguration>();

	}

	public static WifiManagerUtils getInstance(Context paramContext) {
		if (managerUtils == null)
			managerUtils = new WifiManagerUtils(paramContext);
		return managerUtils;
	}

	/**
	 * 获取网卡状态
	 * 
	 * WIFI_AP_STATE_FAILED 14 WIFI_STATE_ENABLED 3 wifi的开启 WIFI_STATE_ENABLING
	 * 2 wifi正在开启 WIFI_STATE_DISABLED 1 wifi关闭 WIFI_STATE_UNKNOWN 4 未知 wifi状态
	 * WIFI_AP_STATE_DISABLING 10 WIFI_AP_STATE_DISABLED 11
	 * WIFI_AP_STATE_ENABLING 12 WIFI_AP_STATE_ENABLED 13
	 * 
	 * @return
	 */
	public int getWifiApStateInt_invoke() {
		int state = -1;
		try {
			state = ((Integer) wifimanager.getClass()
					.getMethod("getWifiApState", new Class[0])
					.invoke(wifimanager, new Object[0])).intValue();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return state;
	}
	
	
	
	/**
	 * 获取wifi状态 3是网卡可用 13是热点可用
	 * 
	 * @return
	 */
	public boolean getWifiAPstate() {
		boolean state = false;
		int i = -1;
		i = wifimanager.getWifiState();
		if (i == 3 || i == 13)
			state = true;
		return state;
	}
	/**
	 * 获取ap State 反射调用 wifimanager的公共方法
	 * 
	 * @return 3 13 是可用状态
	 */
	public boolean getWifiAPstate_invoke() {
		boolean state = false;
		int i = -1;
		try {
			i = ((Integer) wifimanager.getClass()
					.getMethod("getWifiApState", new Class[0])
					.invoke(wifimanager, new Object[0])).intValue();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (i == 3 || i == 13)
			state = true;
		return state;
	}



	// 锁定wifi 当文件大的时候需要锁定, 锁定wifi的设计是为了省电 锁定wifi是防止wifi进入睡眠状态
	public void AcquireWifiLock() {
		mWifiLock.acquire();
	}

	// 释放锁
	public void releaseWifiLock() {
		if (mWifiLock.isHeld()) {
			mWifiLock.release();
		}
	}

	// 创建锁
	public void CreatWifiLock() {
		mWifiLock = wifimanager.createWifiLock("wifiLock");
	}

	
	//开启wifi
	
	/**
	 * 开启wifi
	 */
	public void openWifi() {
		if (!wifimanager.isWifiEnabled()) {
			wifimanager.setWifiEnabled(true);
		}
	}
	/**
	 * 反射开启wifi
	 */
	public void openWifiAp(){
		if(!isWifiApEnabled()){
			Method method1;
			try {
				method1 = wifimanager.getClass().getMethod("getWifiApConfiguration");
			
			method1.setAccessible(true);
			WifiConfiguration configuration = (WifiConfiguration)method1.invoke(wifimanager);
			
			Method method2 = wifimanager.getClass().getMethod("setWifiApEnabled", WifiConfiguration.class,boolean.class);
			method2.invoke(wifimanager,configuration ,false);
			
			
			} catch (NoSuchMethodException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	//关闭wifi
	
	
	/**
	 * 关闭wifi
	 */
	public void closeWifi() {
		if (wifimanager.isWifiEnabled()) {
			wifimanager.setWifiEnabled(false);
		}
	}
	
	/**
	 * 反射调用wifi关闭方法
	 */
	
	public void closeWifiAp() {
		if (isWifiApEnabled()) {
			try {
				Method method = wifimanager.getClass().getMethod(
						"getWifiApConfiguration");
				method.setAccessible(true);

				WifiConfiguration config = (WifiConfiguration) method
						.invoke(wifimanager);

				Method method2 = wifimanager.getClass().getMethod(
						"setWifiApEnabled", WifiConfiguration.class,
						boolean.class);
				method2.invoke(wifimanager, config, false);
			} catch (NoSuchMethodException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	
	
	//是否开启wifi
	/**
	 * 是否开启wifi 如果 
	 */
	public boolean isOpenWifi() {
		if (wifimanager.isWifiEnabled()) {
			return true;
		}
		return false;
	}
	
	/**
	 * 反射调用wifi是否开启 用常规共有方法手机会死
	 * @return
	 */
	public boolean isWifiApEnabled() {
		try {
			Method method = wifimanager.getClass().getMethod("isWifiApEnabled");
			method.setAccessible(true);
			return (Boolean) method.invoke(wifimanager);

		} catch (NoSuchMethodException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}
	
	/**
	 * 扫描wifi 并返回字符串buffer
	 * 
	 * @return
	 */
	@SuppressLint("NewApi")
	public StringBuffer getScanWifiListStr() {
		// 扫描网络前开启
		openWifi();
		buffer = new StringBuffer();
		wifimanager.startScan();
		scanResults = wifimanager.getScanResults();

		for (int i = 0; i < scanResults.size(); i++) {
			buffer.append("The " + i + " : \n");
			// 包含SSID BSSID capabilities level frequency timestamp distance
			// distanceSd isWpsConfigured isXiaomiRouter
			buffer.append("BSSID: " + scanResults.get(i).BSSID + "\n");
			buffer.append("SSID: " + scanResults.get(i).SSID + "\n");
			buffer.append("capabilities :" + scanResults.get(i).capabilities
					+ "\n");
			buffer.append("frequency :" + scanResults.get(i).frequency + "\n");
			buffer.append("level :" + scanResults.get(i).level + "\n");
			buffer.append("timestamp :" + scanResults.get(i).timestamp + "\n\n");
		}
		return buffer;
	}

	/**
	 * 返回ScanList
	 * 
	 * @return
	 */
	public List<ScanResult> getScanWifiList() {
		// 扫描网络前开启
		openWifi();
		wifimanager.startScan(); // getScanResults会立即返回么
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// 不能及时返回消息
		scanResults = wifimanager.getScanResults();
		return scanResults;
	}

	/**
	 * 根据SSID判断某个已经配置好的wifi是否存在
	 * 
	 * @param SSID
	 * @return configuration
	 */
	public WifiConfiguration isExistWifiAp(String SSID) {
		WifiConfiguration configuration = null;
		if (!isOpenWifi()) {
			return configuration;
		}
		// 调用Configure前需要打开wifi
		Iterator<WifiConfiguration> iterator = wifimanager
				.getConfiguredNetworks().iterator();
		if (iterator != null) {
			do {
				if (!iterator.hasNext()) {
					return null;
				}
				configuration = iterator.next();
			} while (!configuration.SSID.equals("\"" + SSID + "\""));
			return configuration;
		}
		return configuration;
	}

	/**
	 * wifi网络热点是否连接上
	 * 
	 * @return
	 */
	public boolean isNetworkConnected() {
		return networkInfo.isConnected();
	}

	/**
	 * 获取当前连接网络的BSSID
	 * 
	 * @return
	 */
	public String getBSSID() {
		if (wifiInfo.getBSSID() == null) {
			return null;
		}
		return wifiInfo.getBSSID();
	}

	/**
	 * 获取当前网络的SSID 及wifi网络名称
	 * 
	 * @return
	 */
	public String getSSID() {
		if (wifiInfo.getSSID() == null) {
			return null;
		}
		return wifiInfo.getSSID();
	}

	/**
	 * 获取当前wifiinfo的ip
	 * 
	 * @return
	 */
	public String getIPAdress() {
		if (wifiInfo != null) {
			String ip = intToIp(wifiInfo.getIpAddress());
			System.out.println("整数型ip" + wifiInfo.getIpAddress() + "");
			return ip;
		}
		return "NULL";
	}

	/**
	 * 获取网络描述
	 * 
	 * @param scanResult
	 *            一个扫描出来的网络ap
	 * @return 包含网络密码保护的描述性文字
	 */
	public String getDesciption(ScanResult scanResult) {
		String descString = "";
		//
		return descString;
	}

	/**
	 * wifi网络下 将ip转换成字符串 ip 按位移再取值得方式将 16进制转换成 0-255的分段数字ip 格式化IP
	 * address，例如：格式化前：，格式化后：192.168.1.109
	 * 
	 * @param ipAddress
	 * @return
	 */
	private String intToIp(int ipAddress) {
		String ipString = String.format("%d.%d.%d.%d", (ipAddress & 0xff),
				(ipAddress >> 8 & 0xff), (ipAddress >> 16 & 0xff),
				(ipAddress >> 24 & 0xff));
		return ipString;
	}

	public boolean connectWifi(String SSID, String password,
			WifiChiperType wifiCipherType) {
		if (!managerUtils.isWifiApEnabled()) {
			return false;
		}

		// 取得wifi状态 是否可用 等待wifi开启
		while (wifimanager.getWifiState() == wifimanager.WIFI_STATE_ENABLING) {

		}

		// 创建wificonfiguration
		WifiConfiguration wifiConfiguration = createWifiConfiguration(SSID,
				password, wifiCipherType);
		if (wifiConfiguration == null) {
			return false;
		}
		// 将已配置的相同SSID的网络从已配置集合中移除
		WifiConfiguration config = isExistWifiAp(SSID);
		if (config != null) {
			wifimanager.removeNetwork(config.networkId);
		}
		int netId = wifimanager.addNetwork(wifiConfiguration);

		// wifimanager.disconnect();
		// 断开其他网络 连接配置好的网络
		wifimanager.enableNetwork(netId, true);

		// wifimanager.reconnect();

		return true;
	}

	// 添加一个config配置的信息的wifi,并连接这个wifi,同时让其他的wifi不可用
	public void addNetwork(WifiConfiguration config) {
		int i = wifimanager.addNetwork(config);

		wifimanager.enableNetwork(i, true);
	}

	// 根据netID连接指定wifi
	public void connectWifibyId(int netID) {
		if (netID > wifiConfigurations.size()) {
			return;
		}

		wifimanager
				.enableNetwork(wifiConfigurations.get(netID).networkId, true);
	}

	// 根据netID断开某个wifi
	public void disconnectWifi(int netID) {
		wifimanager.disableNetwork(netID);
	}

	// 移除某个网络
	public void removeWifi(int netID) {
		wifimanager.removeNetwork(netID);

	}



	/**
	 * 创建wifi
	 * 
	 * @param ssid
	 * @param password
	 * @param encrypTpye
	 */
	public boolean createWifiAp(String ssid, String password,
			WifiChiperType encrypTpye) {
		//此方法不需要反射调用 就可以关闭wifi
		managerUtils.closeWifi();
		//managerUtils.closeWifiAp();

		WifiConfiguration wifiConfiguration = createWifiConfiguration(ssid,
				password, encrypTpye);
		if (wifiConfiguration == null) {
			return false;
		}
		// 调用wifimanager的私有方法：setWifiEnable
		// 创建wifi
		createWifi(wifiConfiguration);
		return true;
	}

	private void createWifi(WifiConfiguration wifiConfiguration) {
		
		//反射方法才可以传递WifiConfiguration
		try {
			Method method = this.wifimanager.getClass().getMethod(
					"setWifiApEnabled", WifiConfiguration.class, boolean.class);
			method.invoke(wifimanager, wifiConfiguration, true);

		} catch (NoSuchMethodException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * 
	 * @param ssid
	 * @param password
	 * @param encrypTpye
	 * @return
	 */
	private WifiConfiguration createWifiConfiguration(String ssid,
			String password, WifiChiperType encrypTpye) {
		WifiConfiguration wifiConfiguration = new WifiConfiguration();
		
		  wifiConfiguration.allowedAuthAlgorithms.clear();
		  wifiConfiguration.allowedGroupCiphers.clear();
		  wifiConfiguration.allowedKeyManagement.clear();
		  wifiConfiguration.allowedPairwiseCiphers.clear();
		  wifiConfiguration.allowedProtocols.clear();

		// encrypTpye 加密类型
		if (encrypTpye == WifiChiperType.WIFICIPHER_NOPASS) {
			wifiConfiguration.SSID = ssid;
			wifiConfiguration.wepKeys[0] = "";
			wifiConfiguration.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
			wifiConfiguration.wepTxKeyIndex = 0;
		}
		if (encrypTpye == WifiChiperType.WIFICIPHER_WEP) {
			
			wifiConfiguration.SSID = ssid;
			wifiConfiguration.preSharedKey = password;
			wifiConfiguration.hiddenSSID = true;
			/** WPA is not used; plaintext or static WEP could be used. */
			wifiConfiguration.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
			/** Shared Key authentication (requires static WEP keys) */
			wifiConfiguration.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED);
			/**
			 * WEP40 = WEP (Wired Equivalent Privacy) with 40-bit key (original 802.11)
			 */
			wifiConfiguration.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
			/** WEP104 = WEP (Wired Equivalent Privacy) with 104-bit key */
			wifiConfiguration.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
			/** AES in Counter mode with CBC-MAC [RFC 3610, IEEE 802.11i/D7.0] */
			// 数据编码完整性校验
			wifiConfiguration.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
			/** Temporal Key Integrity Protocol [IEEE 802.11i/D7.0] */
			// 数据加密传输
			wifiConfiguration.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
		}
		if (encrypTpye == WifiChiperType.WIFICIPHER_WPA) {

			wifiConfiguration.SSID = ssid;
			wifiConfiguration.preSharedKey = password;
			wifiConfiguration.hiddenSSID = true;
			//根据源代码的注释选择
			wifiConfiguration.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);

			wifiConfiguration.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);

			wifiConfiguration.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
			wifiConfiguration.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);

			wifiConfiguration.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
			wifiConfiguration.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);

			wifiConfiguration.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
			wifiConfiguration.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

		} else {
			return null;
		}
		return wifiConfiguration;
	}

}
