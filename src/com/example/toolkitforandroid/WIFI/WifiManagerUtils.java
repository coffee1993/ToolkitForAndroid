package com.example.toolkitforandroid.WIFI;


/**
 * wifi Utils 管理Wifi wifi等基本使用
 * 
 * 
 * 带 Ap的都跟创建热点有关  ，都为隐藏API需要反射调用
 * 
 * 不带Ap的就是网卡能搜索到的wifi
 * 
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
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.NetworkInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.nfc.Tag;
import android.os.Handler;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;

/**
 * 
 * @author zhangyi
 * 
 */
public class WifiManagerUtils {

	private static final String TAG = "WIFI_LOG";

	private WifiManager wifimanager;
	private WifiInfo wifiInfo;
	private DhcpInfo dhcpInfo;
	private NetworkInfo networkInfo;
	private StringBuffer buffer;
	private static Context mContext;
	private List<ScanResult> scanResults = null; // 扫描的wifi结果集
	private List<WifiConfiguration> wifiConfigurations = null;
	private ConnectivityManager connectivityManager;
	
	private static WifiManagerUtils managerUtils = null;

	// 需要打开锁
	private WifiManager.WifiLock mWifiLock;

	public static enum WifiChiperType {
		WIFICIPHER_WEP, WIFICIPHER_WPA,WIFICIPHER_WPA2, WIFICIPHER_NOPASS
	}

	private WifiManagerUtils(Context pContext) {
		mContext = pContext;
		wifimanager = (WifiManager) pContext
				.getSystemService(Context.WIFI_SERVICE); // 这行代码写在这里好还是写在字段那里好
		wifiInfo = wifimanager.getConnectionInfo(); // 获取当前连接的wifi网络
		dhcpInfo = wifimanager.getDhcpInfo();
		wifiConfigurations = new ArrayList<WifiConfiguration>();

	}
	public static WifiManagerUtils getInstance(Context paramContext) {
		if (managerUtils == null)
			Log.i(TAG, "wifiManager 第一次初始化");
			managerUtils = new WifiManagerUtils(paramContext);
		return managerUtils;
	}
	/**
	 * 获取网卡状态 WIFI_STATE
	 *	  
	 * @return	WIFI_STATE_DISABLING 0
	 * 			WIFI_STATE_DISABLED  1
	 * 			WIFI_STATE_ENABLED	2
     *	 		WIFI_STATE_ENABLING 3
     *	 		WIFI_STATE_UNKNOWN	4
	 */
	public int getWifiStateInt() {
		int state = wifimanager.getWifiState();
		return state;
	}
			
	/**
	 * 获取ap State 反射调用 wifimanager的公共方法
	 * 
	 * @return 3 13 是可用状态
	 */
	public boolean getWifiApState_invoke() {
		boolean state = false;
		int i = -1;
		try {
			i = ((Integer) wifimanager.getClass()
					.getMethod("getWifiApState", new Class[0])
					.invoke(wifimanager, new Object[0])).intValue();
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (i == 13)
			state = true;
		return state;
	}

	/**
	 * 获取热点状态WIFI_AP_STATE 隐藏api 反射
	 * @return  
	 * 			WIFI_AP_STATE_DISABLING 10 
	 * 			WIFI_AP_STATE_DISABLED 11
	 * 			WIFI_AP_STATE_ENABLING 12 
	 * 			WIFI_AP_STATE_ENABLED 13
	 * 			WIFI_AP_STATE_FAILED 14 
	 */
	
	public int getWifiApStateInt_invoke() {
		int state = -1;
		try {
			state = ((Integer) wifimanager.getClass()
					.getMethod("getWifiApState", new Class[0])
					.invoke(wifimanager, new Object[0])).intValue();
		} catch (Exception e) {
			e.printStackTrace();
		}
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

	
	/**
	 * 开启wifi
	 */
	public void openWifi() {
		
		Log.i(TAG,"开启wifi");
		if (!wifimanager.isWifiEnabled()) {
			wifimanager.setWifiEnabled(true);
		}
	}
	
	/**
	 * set WIFI_AP_STATE_ENABLED true
	 * 反射开启热点状态
	 */
	public void openWifiApEnabled(){
		if(!isWifiApEnabled()){
			Method method1;
			try {
				method1 = wifimanager.getClass().getMethod("getWifiApConfiguration");
			
			method1.setAccessible(true);
			
			WifiConfiguration configuration = (WifiConfiguration)method1.invoke(wifimanager);
			
			Method method2 = wifimanager.getClass().getMethod("setWifiApEnabled", WifiConfiguration.class,boolean.class);
			method2.invoke(wifimanager,configuration ,false);
			
			} catch (NoSuchMethodException e) {
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * 关闭wifi
	 */
	public void closeWifi() {
		if (wifimanager.isWifiEnabled()) {
			wifimanager.setWifiEnabled(false);
		}
	}
	
	
	/**
	 *  set WIFI_AP_STATE_ENABLED false
	 * 反射关闭热点状态  
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
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				e.printStackTrace();
			}
		}
	}


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
	 * 反射调用wifi是否开启 
	 * @return
	 */
	public boolean isWifiApEnabled() {
		try {
			Method method = wifimanager.getClass().getMethod("isWifiApEnabled");
			method.setAccessible(true);
			return (Boolean) method.invoke(wifimanager);

		} catch (NoSuchMethodException e) {
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
			buffer.append("The " + i + getClass().getSimpleName()+" : \n");
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
		
		wifimanager.startScan(); // getScanResults会立即返回么 最好写成广播的形式  
		Log.i(TAG,"开始扫描wifi>>>>>>>");
		try {
			Thread.sleep(1500);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		// 不能及时返回消息
		scanResults = wifimanager.getScanResults();
		//wifimanager.getScanResults();
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
			Log.i(TAG,getClass().getSimpleName()+" :wifi 已关闭");
			return configuration;
		}
		// 调用Configure前需要打开wifi

		Iterator<WifiConfiguration> iterator = wifimanager
				.getConfiguredNetworks().iterator();
		if (iterator != null) {
			while(iterator.hasNext()){
				if((configuration = iterator.next())!= null){			
					Log.i(TAG,getClass().getSimpleName()+": 查询到已配置的网络："+configuration.SSID+" "+configuration.networkId);		
					if(!TextUtils.isEmpty(configuration.SSID)){
						if(configuration.SSID.equals(SSID)){
							Log.i(TAG,getClass().getSimpleName()+"： 返回的网络："+configuration.SSID+" "+configuration.networkId);
							return configuration;
						}
					}
				}
			}
		}else{
			Log.i(TAG,getClass().getSimpleName()+"： iterator为空 返回");			
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
	 * 获取本机已经创建的热点名称
	 * 
	 * 
	 */
	public String getApSSID(){
		
		/**
		 *  
		 * Gets the Wi-Fi AP Configuration.
		 * @return AP details in WifiConfiguration
		 *
		 * @hide Dont open yet
     	
    	public WifiConfiguration getWifiApConfiguration() {
        	try {
            return mService.getWifiApConfiguration();
        	}	 catch (RemoteException e) {
            	return null;
        	}
    	}
		 */
		try {
			//反射方法
			Method method = wifimanager.getClass().getDeclaredMethod("getWifiApConfiguration", new Class[0]);
			if(method==null){
				return null;
			}
			//返回对象
			Object object = method.invoke(wifimanager, new Object[0]);
			if(object!=null){
				WifiConfiguration wifiConfiguration = (WifiConfiguration)object;
				if(wifiConfiguration.SSID!=null){
					return wifiConfiguration.SSID;
				}
				
			}
			
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
		return null;
		
		
	}
	
	/**
	 * 获取当前wifiinfo的ip,即本地ip
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

	public String getServerIPAddress() {
        DhcpInfo mDhcpInfo = wifimanager.getDhcpInfo();
        return intToIp(mDhcpInfo.gateway); //why not is ipAdress???
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
	@SuppressLint("DefaultLocale")
	private String intToIp(int ipAddress) {
		String ipString = String.format("%d.%d.%d.%d", (ipAddress & 0xff),
				(ipAddress >> 8 & 0xff), (ipAddress >> 16 & 0xff),
				(ipAddress >> 24 & 0xff));
		return ipString;
	}

	
	/**
	 * 
	 * 连接wifi 
	 * @param SSID
	 * @param password
	 * @param wifiCipherType
	 * @return
	 */
	public boolean connectWifi(String SSID, String password,
			WifiChiperType wifiCipherType) {
		if (!managerUtils.isOpenWifi()) {
			Log.i(TAG,getClass().getSimpleName()+" :wifi不可用 wifi开启："+
			managerUtils.isOpenWifi());
			return false;
		}
		
		Log.i(TAG,getClass().getSimpleName()+": 连接wifi");

		// 一定要在wifi 在ENABlED状态下
		while (wifimanager.getWifiState() != WifiManager.WIFI_STATE_ENABLED) {
			Log.i(TAG,getClass().getSimpleName()+" :循环...");
		}

		// 创建wificonfiguration
		WifiConfiguration wifiConfiguration = createWifiConfiguration(SSID,
				password, wifiCipherType);
		
		if (wifiConfiguration == null) {
			Log.i(TAG,getClass().getSimpleName()+" : createWifiConfiguration 为空 创建失败 返回 false ");
			return false;
		}

		//将原来同名的网络配置移除
		WifiConfiguration config = isExistWifiAp(SSID);
		if (config != null) {	
			Log.i(TAG,getClass().getSimpleName()+" 移除:"+config.SSID+" "+config.networkId);
			boolean isRemove= wifimanager.removeNetwork(config.networkId);
			Log.i(TAG,getClass().getSimpleName()+" 移除已经配置好的相同SSID的网络:"+isRemove);
		}
		
		if(config==null){
			Log.i(TAG,getClass().getSimpleName()+" :configuration：null");
			return false;
		}
		//id为-1
		// 断开其他网络 连接配置好的网络
		int netId = wifimanager.addNetwork(wifiConfiguration);
		
		Log.i(TAG,getClass().getSimpleName()+" :添加到Network中 id为："+netId);
		//wifimanager.disconnect();
		
		boolean flag = false;
		
		if(netId!=-1){			
			//这个函数只是让网卡去连接wifi并不是已经连接上wifi了 所以需要检查网卡状态 需要为2才表示网卡打开
			flag =  wifimanager.enableNetwork(netId, true);
		}else{
			return false;
		}
		//wifimanager.saveConfiguration();
		//wifimanager.reconnect();
		//wifimanager.reassociate();
		 
		//做个定时器循环检测wifi网卡状态 让网卡的状态由可用 变为 运行  2--0
		int status = wifimanager.getConfiguredNetworks().get(netId).status;		
		/*  this is the network we are currently connected to
		   	public static final int CURRENT = 0;
	        /** supplicant will not attempt to use this network *//*
	        public static final int DISABLED = 1;
	        /** supplicant will consider this network available for association *//*
	        public static final int ENABLED = 2;
		*/
		int count = 5;
		while((status=wifimanager.getConfiguredNetworks().get(netId).status)!=0){
			Log.i(TAG,getClass().getSimpleName()+" :网卡状态值:"+status);
			openWifiApEnabled();
			count--;
			if(count<1){
				flag=false;
				break;
			}
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		return flag;
	}
	
	/**
	 * 判断是否连接上WiFi
	 * @return
	 */
	public boolean isConnected(){
		boolean flag = false;
		// 获取NetWorkInfo信息
		NetworkInfo networkInfo = ((ConnectivityManager) mContext
				.getSystemService(Context.CONNECTIVITY_SERVICE))
				.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
		
		flag = networkInfo.isConnected();
		
		return flag;
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
			WifiChiperType encrypTpye,final Handler mHandler) {
		
		
		managerUtils.closeWifi();
		//创建 wifiConfiguration 
		WifiConfiguration wifiConfiguration = createWifiConfiguration(ssid,
				password, encrypTpye);
		if (wifiConfiguration == null) {
			return false;
		}
		// 反射调用wifimanager带有configuration的私有方法：setWifiApEnable 创建wifi
		createWifi(wifiConfiguration);	
		//计时器  循环检测 isWifiApEnabled
		TimerCheck timerCheck = new TimerCheck() {
			@Override
			public void doTimerOutWork() {
					stop();
			}
			@Override
			public void doTimerCheckWork() {
				
				if(managerUtils.isWifiApEnabled()){
					Log.i(TAG,"做wifi创建计时器循环检测wifi状态 ApEnable:"+managerUtils.isWifiApEnabled()); //true
					mHandler.sendEmptyMessage(1);
					stop();					
				}
			}
		};
		timerCheck.start(10, 1000);
		
		return true;
	}
	
	private void createWifi(WifiConfiguration wifiConfiguration) {
		
		//反射方法才可以传递WifiConfiguration
		try {
			Method method = this.wifimanager.getClass().getMethod(
					"setWifiApEnabled", WifiConfiguration.class, boolean.class);
			method.invoke(wifimanager, wifiConfiguration, true);

		} catch (NoSuchMethodException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (InvocationTargetException e) {
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
			wifiConfiguration.SSID = "\""+ ssid+"\"";;
			wifiConfiguration.wepKeys[0] = "";
			wifiConfiguration.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
			wifiConfiguration.wepTxKeyIndex = 0;
		}
		if (encrypTpye == WifiChiperType.WIFICIPHER_WEP) {			
			wifiConfiguration.SSID = "\""+ ssid+"\"";;
			wifiConfiguration.preSharedKey = "\""+ password+"\"";;
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
			wifiConfiguration.SSID = "\""+ ssid+"\"";
			wifiConfiguration.preSharedKey ="\""+ password+"\"";
			wifiConfiguration.hiddenSSID = false; //显示密码 调试
			//根据源代码的注释选择 
			wifiConfiguration.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);

			wifiConfiguration.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);

			wifiConfiguration.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
			wifiConfiguration.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);

			wifiConfiguration.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
			wifiConfiguration.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
			//连接wifi是不是这个不能设置
			wifiConfiguration.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
			//WPA
			wifiConfiguration.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
			//强行开启
			wifiConfiguration.status = WifiConfiguration.Status.ENABLED;
		} else {
			//没有密码类型return null
			return null;
		}
		Log.i(TAG,getClass().getSimpleName()+": "+wifiConfiguration.toString());
		return wifiConfiguration;
	}

}
