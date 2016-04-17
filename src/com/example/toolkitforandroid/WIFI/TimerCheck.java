package com.example.toolkitforandroid.WIFI;

/**
 * the TimerCheck Uitls , do some work need timer 
 * @author zhangyi
 *
 */
public abstract class TimerCheck {
	private int mCount = 0; 
	private int mTimeOutCount = 100; //max times
	private int mSleepTime = 1000; //thread sleep time per work 
	private boolean mExitFlag = false; 
	private Thread mThread; //timer thread 
	
	public TimerCheck() {
		mThread = new Thread(new Runnable() {
			
			public void run() {
				while(!mExitFlag){
					mCount++;
					if(mCount<=mTimeOutCount){
						doTimerCheckWork();
						try {
							Thread.sleep(mSleepTime);
						} catch (InterruptedException e) {
							e.printStackTrace();
							stop();
						}
					}else{
						doTimerOutWork();
					}
					
				}
				
			}	
		});
		
	}
	
	/**
	 * doing work in new Thread ,not in UI Thread
	 */
	public abstract void doTimerOutWork();
	/**
	 * doing work in new Thread ,not in UI Thread
	 */
	public abstract void doTimerCheckWork();
	
	public void start(int timeOutCount,int sleepTime){
		this.mTimeOutCount = timeOutCount;
		this.mSleepTime = sleepTime;
		this.mThread.start();
	}
	
	public void stop(){
		mExitFlag = true;	
	}
}
