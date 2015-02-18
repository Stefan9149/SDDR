package server;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

public class Delegation {
	private String delegatedName;
	private Date createdTime;
	private long expireTime;
	private boolean propagation;
	private String rights;
	
	Delegation(String delegatedName, long expireTime, String right, boolean propagation) {
		this.delegatedName = delegatedName;
		this.expireTime = expireTime;
		this.rights = right;
		this.propagation = propagation;
		Calendar cal = Calendar.getInstance();
		createdTime = cal.getTime(); 
	}
	//later update delegation, keep old createdtime
	Delegation(String delegatedName, Date createdTime, long expireTime, String right, boolean propagation) {
		this.delegatedName = delegatedName;
		this.expireTime = expireTime;
		this.rights = right;
		this.propagation = propagation;
		this.createdTime = createdTime;
	}
	//get from backup file
	Delegation(String record) {
		String[] temp = record.split(";");
		delegatedName = temp[0];
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		try {
			createdTime = dateFormat.parse(temp[1]);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		expireTime = Long.valueOf(temp[2]);
		propagation = Boolean.valueOf(temp[3]);
		rights = temp[4];
	}
	
	public String writeInfo() {
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		return (delegatedName + ";" + dateFormat.format(createdTime) + ";" + String.valueOf(expireTime) 
				+ ";" + String.valueOf(propagation) + ";" + rights);
	}
	
	public Date getCreatedTime() {
		return createdTime;
	}
	
	public long getExpireTime() {
		return expireTime;
	}
	public String getRights() {
		return rights;
	}
	
	public String getUser() {
		return delegatedName;
	}
	public boolean canRead() {
		if(rights.equals("R")||rights.equals("WR")) {
			return true;
		}
		return false;
	}
	
	public boolean canWrite() {
		if(rights.equals("W")||rights.equals("WR")) {
			return true;
		}
		return false;
	}
	
	public boolean toAll() {
		return delegatedName.equals("ALL");
	}
	
	//calculate available time left
	public long leftTime() {
		Calendar cal = Calendar.getInstance();
		long now = cal.getTime().getTime(); 
		return (expireTime*1000 - (now - createdTime.getTime()))/1000;
	}
	
	public boolean isExpired() {
		Calendar cal = Calendar.getInstance();
		long now = cal.getTime().getTime(); 
		return (now-createdTime.getTime()) >= (expireTime*1000);
	}
	
	public boolean canPropagate() {
		return propagation;
	}
}
