package de.robv.android.xposed;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

import java.io.File;
import java.security.Provider;

import android.content.Context;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;

public class SamsungHelper {

	private static final String SAMSUNG_CONTEXT = "com.samsung.android.providers.context";
	private static final String SHEALTH_SERVICE = "com.sec.android.service.health";
	private static final String PRIVATE_SERVICE = "com.samsung.android.personalpage.service";
	private static final String SECURITY_LOG = "com.samsung.android.securitylogagent";

	public static boolean isSamsungRom() {
		if (new File("/system/framework/twframework.jar").isFile()) {
			return true;
		}

		return false;
	}

	/*
	 * Disable enforced Samsung MDFPP (Mobile Device Fundamentals Protection
	 * Profile). Keeping Mdfpp enforced leads to disable some required
	 * cryptographic modules, and this may cause a crashes or even a bootloop!
	 */
	public static void hookMdpp() {

		final int DEX2OAT_NEEDED = 1;
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

		try {
			findAndHookMethod("com.samsung.android.security.CCManager", classLoader, "isMdfEnforced", XC_MethodReplacement.returnConstant(false));
		} catch (Throwable e) {
			XposedBridge.log(e);
		}

		try {
				// Force dexOptNeeded
				findAndHookMethod("dalvik.system.DexFile", classLoader, "dexOptNeededResultCode", XC_MethodReplacement.returnConstant(DEX2OAT_NEEDED));
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

		if (VERSION.SDK_INT < VERSION_CODES.M) {

			try {
				// Return non Fips mode
				findAndHookMethod("com.android.org.conscrypt.OpenSSLProvider", classLoader, "checkFipsMode", XC_MethodReplacement.returnConstant(false));
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

			try {
				// Do not call nativeCheckWhitelist and return false to disable
				// Fips
				findAndHookMethod("com.android.org.conscrypt.OpenSSLProvider", classLoader, "nativeCheckWhitelist", XC_MethodReplacement.returnConstant(false));
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

			try {
				// Disable Mdpp
				findAndHookMethod("com.android.org.conscrypt.OpenSSLProvider", classLoader, "setMDPP", boolean.class, new XC_MethodHook() {
					@Override
					protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
						param.args[0] = false;
					}

				});
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

			try {
				// Do NOT remove unsupported services (by Fips) from openssl
				// provider
				findAndHookMethod("com.android.org.conscrypt.OpenSSLProvider", classLoader, "removeUnsupportedServices", XC_MethodReplacement.DO_NOTHING);
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

			try {
				// Restore unsupported Fips services at the end of OpenSSL
				// initialization
				final Class<?> mServices = XposedHelpers.findClass("org.apache.harmony.security.fortress.Services", classLoader);
				XposedHelpers.findAndHookConstructor("com.android.org.conscrypt.OpenSSLProvider", classLoader, String.class, new XC_MethodHook() {
					@Override
					protected void afterHookedMethod(MethodHookParam param) throws Throwable {
						try {
	                        XposedHelpers.callMethod(param.thisObject, "restoreUnsupportedServices");
	                        XposedHelpers.callStaticMethod(mServices, "setNeedRefresh");
                        } catch (Throwable e) {
            				// Ignore it
            				// These methods may not exist on some TW Roms
                        }

					}
				});
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

			try {
				// Force DefaultHostnameVerifier to set mdpp mode to false and
				// use
				// the default (GS6)
				XposedHelpers.findAndHookConstructor("javax.net.ssl.DefaultHostnameVerifier", classLoader, boolean.class, new XC_MethodHook() {
					@Override
					protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
						param.args[0] = false;

					}
				});
			} catch (Throwable e) {
				// Ignore it
				// This class may not exist on some TW Roms
			}

			try {
				// Force DefaultHostnameVerifier to set mdpp version to null and
				// use
				// the default (Note5)
				XposedHelpers.findAndHookConstructor("javax.net.ssl.DefaultHostnameVerifier", classLoader, String.class, new XC_MethodHook() {
					@Override
					protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
						param.args[0] = null;

					}
				});
			} catch (Throwable e) {
				// Ignore it
				// This class may not exist on some TW Roms
			}

			try {
				// Force HttpsURLConnection to use defaultHostnameVerifier
				// instead
				// of mdppHostnameVerifier by setting mdpp version to null
				// (Note5)
				findAndHookMethod("javax.net.ssl.HttpsURLConnection", classLoader, "updateMdfVersion", XC_MethodReplacement.returnConstant(null));
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

			try {
				// Force HttpsURLConnection to use defaultHostnameVerifier
				// instead
				// of mdppHostnameVerifier (GS6)
				findAndHookMethod("javax.net.ssl.HttpsURLConnection", classLoader, "isMdfEnforced", XC_MethodReplacement.returnConstant(false));
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

			try {
				// Force HttpsURLConnection to use defaultHostnameVerifier
				// instead
				// of mdppHostnameVerifier (Note5)
				findAndHookMethod("java.util.MdfppReflectionUtils", classLoader, "isMdfEnforced", XC_MethodReplacement.returnConstant(false));
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

			try {
				// Ignore Mdpp checks
				findAndHookMethod("org.apache.harmony.security.fortress.Services", classLoader, "checkMDPP", Provider.class, XC_MethodReplacement.DO_NOTHING);
			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}

			try {
				// Fixes a bootloop on Note 5 devices
				// Samsung GNote 5 FWs has a stange complicated
				// "awaitFinalization"
				// method that keep waiting for ever, we set a timeout of 10
				// secondes
				findAndHookMethod("java.lang.ref.FinalizerReference$Sentinel", classLoader, "awaitFinalization", long.class, new XC_MethodHook() {
					@Override
					protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
						param.args[0] = 10000L;
					}
				});

			} catch (Throwable e) {
				// Ignore it
				// This method may not exist on some TW Roms
			}
		}

	}

	/**
	 * Disable secure storage (incompatible with Xposed). We need to disable it
	 * to get some services to work with Xposed (Private Mode, SHealth...)
	 * 
	 * @param reportedPackageName
	 * @param classLoader
	 */
	public static void hookSamsungSecureStorage(String reportedPackageName, ClassLoader classLoader) {
		if (reportedPackageName.equals(SAMSUNG_CONTEXT) || reportedPackageName.equals(PRIVATE_SERVICE) || reportedPackageName.equals(SHEALTH_SERVICE)) {
			try {
				findAndHookMethod("com.sec.android.securestorage.SecureStorage", classLoader, "isSupported", XC_MethodReplacement.returnConstant(false));
			} catch (Throwable e) {
				XposedBridge.log(e);
			}
		}

		if (reportedPackageName.equals(PRIVATE_SERVICE)) {
			try {
				findAndHookMethod(PRIVATE_SERVICE + ".util.SecureProperties$SecureStorageProperties", classLoader, "getInstance", Context.class, XC_MethodReplacement.returnConstant(null));
			} catch (Throwable e) {
				XposedBridge.log(e);
			}
		}

		if (reportedPackageName.equals(SECURITY_LOG)) {
			try {
				XposedHelpers.findAndHookMethod("com.sec.android.securestorage.SecureStorageJNI", classLoader, "isSupported", XC_MethodReplacement.returnConstant(false));
			} catch (Throwable e) {
				XposedBridge.log(e);
			}
		}
	}

}
