#import "AFNetworking.h"
#import "BaseAuthenticator.h"
#import "../ios_uikit_bridge.h"
#import "../utils.h"
#include "jni.h"
#import <CommonCrypto/CommonCrypto.h>

typedef void(^XSTSCallback)(NSString *xsts, NSString *uhs);

@implementation MicrosoftAuthenticator

#pragma mark - 离线账号功能

// 生成离线UUID（基于Java版Minecraft的算法）
- (NSString *)generateOfflineUUID:(NSString *)username {
    if (!username || username.length == 0) {
        return @"00000000-0000-0000-0000-000000000000";
    }
    
    // 转换为小写并去除空格（与Java版行为一致）
    NSString *normalizedUsername = [[username lowercaseString] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    const char *utf8String = [normalizedUsername UTF8String];
    
    if (!utf8String) {
        return @"00000000-0000-0000-0000-000000000000";
    }
    
    unsigned char digest[16];
    CC_MD5(utf8String, (CC_LONG)strlen(utf8String), digest);
    
    // 设置UUID版本为3（基于名称的MD5 UUID）
    digest[6] = (digest[6] & 0x0F) | 0x30;
    digest[8] = (digest[8] & 0x3F) | 0x80;
    
    // 格式化为UUID字符串
    return [NSString stringWithFormat:@"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            digest[0], digest[1], digest[2], digest[3],
            digest[4], digest[5], digest[6], digest[7],
            digest[8], digest[9], digest[10], digest[11],
            digest[12], digest[13], digest[14], digest[15]];
}

// 检查用户名是否有效
- (BOOL)isValidOfflineUsername:(NSString *)username {
    if (!username || username.length == 0) {
        return NO;
    }
    
    // Minecraft用户名规则：3-16个字符，只能包含字母、数字、下划线
    if (username.length < 3 || username.length > 16) {
        return NO;
    }
    
    // 检查是否只包含允许的字符
    NSCharacterSet *allowedCharacters = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"];
    NSCharacterSet *usernameCharacters = [NSCharacterSet characterSetWithCharactersInString:username];
    
    if (![allowedCharacters isSupersetOfSet:usernameCharacters]) {
        return NO;
    }
    
    return YES;
}

// 创建离线账号
- (void)createOfflineAccount:(NSString *)username callback:(Callback)callback {
    if (![self isValidOfflineUsername:username]) {
        NSString *errorMsg = localize(@"login.offline.error.invalidUsername", nil);
        if (!errorMsg) {
            errorMsg = @"用户名无效。Minecraft用户名必须为3-16个字符，只能包含字母、数字和下划线。";
        }
        callback(errorMsg, NO);
        return;
    }
    
    NSString *progressMsg = localize(@"login.offline.progress.creating", nil);
    if (!progressMsg) {
        progressMsg = @"创建离线账号...";
    }
    callback(progressMsg, YES);
    
    // 生成确定性UUID
    NSString *uuid = [self generateOfflineUUID:username];
    
    // 设置认证数据
    NSMutableDictionary *authData = [self.authData mutableCopy];
    if (!authData) {
        authData = [NSMutableDictionary dictionary];
    }
    
    authData[@"username"] = username;
    authData[@"profileId"] = [NSString stringWithFormat:@"%@-%@-%@-%@-%@",
        [uuid substringWithRange:NSMakeRange(0, 8)],
        [uuid substringWithRange:NSMakeRange(8, 4)],
        [uuid substringWithRange:NSMakeRange(12, 4)],
        [uuid substringWithRange:NSMakeRange(16, 4)],
        [uuid substringWithRange:NSMakeRange(20, 12)]
    ];
    authData[@"accessToken"] = @"offline";
    authData[@"profilePicURL"] = [NSString stringWithFormat:@"https://mc-heads.net/head/%@/120", authData[@"profileId"]];
    authData[@"xboxGamertag"] = username;
    authData[@"xuid"] = [NSString stringWithFormat:@"offline_%@", uuid];
    authData[@"expiresAt"] = @((long)[[NSDate date] timeIntervalSince1970] + 86400 * 365); // 1年有效期
    authData[@"isOffline"] = @YES;
    
    self.authData = authData;
    
    // 保存更改
    if ([self saveChangesForOfflineAccount]) {
        callback(nil, YES);
    } else {
        NSString *errorMsg = localize(@"login.offline.error.saveFailed", nil);
        if (!errorMsg) {
            errorMsg = @"保存离线账号失败。";
        }
        callback(errorMsg, NO);
    }
}

// 离线账号的保存逻辑
- (BOOL)saveChangesForOfflineAccount {
    // 对于离线账号，我们不需要保存令牌到钥匙串
    // 只需要调用父类的保存方法
    BOOL success = [super saveChanges];
    if (success) {
        NSLog(@"[MicrosoftAuthenticator] 离线账号保存成功: %@", self.authData[@"username"]);
    } else {
        NSLog(@"[MicrosoftAuthenticator] 离线账号保存失败: %@", self.authData[@"username"]);
    }
    return success;
}

// 检测输入是否为离线用户名（而非Microsoft授权码）
- (BOOL)isOfflineUsernameInput:(NSString *)input {
    if (!input || input.length == 0) {
        return NO;
    }
    
    // Microsoft授权码通常是较长的字符串，包含特殊字符
    // 离线用户名应该是较短的合法Minecraft用户名
    if (input.length > 50) {
        return NO; // 太长了，不可能是用户名
    }
    
    // 检查是否是有效的离线用户名
    return [self isValidOfflineUsername:input];
}

#pragma mark - 修改现有方法支持离线账号

// 修改：登录方法，支持离线账号检测
- (void)loginWithCallback:(Callback)callback {
    NSString *input = self.authData[@"input"];
    
    if (!input) {
        callback(@"输入为空", NO);
        return;
    }
    
    // 检测是否是离线账号用户名
    if ([self isOfflineUsernameInput:input]) {
        NSLog(@"[MicrosoftAuthenticator] 检测到离线用户名: %@", input);
        [self createOfflineAccount:input callback:callback];
    } else {
        // 否则按原逻辑处理Microsoft登录
        NSLog(@"[MicrosoftAuthenticator] 检测到Microsoft授权码");
        [self acquireAccessToken:self.authData[@"input"] refresh:NO callback:callback];
    }
}

// 修改：刷新令牌方法，支持离线账号
- (void)refreshTokenWithCallback:(Callback)callback {
    // 检查是否是离线账号
    if ([self.authData[@"isOffline"] boolValue]) {
        NSLog(@"[MicrosoftAuthenticator] 离线账号跳过令牌刷新: %@", self.authData[@"username"]);
        // 离线账号不需要刷新，直接返回成功
        callback(nil, YES);
        return;
    }
    
    // 原有的Microsoft账号刷新逻辑
    if (!self.tokenData) {
        showDialog(localize(@"Error", nil), @"Failed to load account tokens from keychain");
        callback(nil, YES);
        return;
    }

    if ([[NSDate date] timeIntervalSince1970] > [self.authData[@"expiresAt"] longValue]) {
        [self acquireAccessToken:self.tokenData[@"refreshToken"] refresh:YES callback:callback];
    } else {
        callback(nil, YES);
    }
}

// 修改：保存更改方法，支持离线账号
- (BOOL)saveChanges {
    // 检查是否是离线账号
    if ([self.authData[@"isOffline"] boolValue]) {
        return [self saveChangesForOfflineAccount];
    }
    
    // 原有的Microsoft账号保存逻辑
    NSString *accessToken = self.authData[@"accessToken"];
    NSString *refreshToken = self.authData[@"msaRefreshToken"];
    
    if (!accessToken || !refreshToken) {
        NSLog(@"[MicrosoftAuthenticator] 保存失败：accessToken或refreshToken为空");
        return NO;
    }
    
    BOOL savedToKeychain = [self setAccessToken:accessToken refreshToken:refreshToken];
    if (!savedToKeychain) {
        showDialog(localize(@"Error", nil), @"Failed to save account tokens to keychain");
        return NO;
    }
    
    NSMutableDictionary *mutableAuthData = [self.authData mutableCopy];
    [mutableAuthData removeObjectsForKeys:@[@"accessToken", @"msaRefreshToken"]];
    self.authData = mutableAuthData;
    
    return [super saveChanges];
}

#pragma mark - 钥匙串相关方法

// 修改：钥匙串查询方法，支持离线账号
+ (NSDictionary *)keychainQueryForKey:(NSString *)profile extraInfo:(NSDictionary *)extra {
    // 如果是离线账号的xuid（以"offline_"开头），不使用钥匙串
    if (profile && [profile hasPrefix:@"offline_"]) {
        return nil;
    }
    
    NSMutableDictionary *dict = [@{
        (id)kSecClass: (id)kSecClassGenericPassword,
        (id)kSecAttrService: @"AccountToken",
        (id)kSecAttrAccount: profile ?: @"",
    } mutableCopy];
    
    if (extra) {
        [dict addEntriesFromDictionary:extra];
    }
    return dict;
}

// 修改：tokenData getter，支持离线账号
- (NSDictionary *)tokenData {
    if ([self.authData[@"isOffline"] boolValue]) {
        // 离线账号返回nil，因为不需要令牌数据
        return nil;
    }
    
    NSString *xuid = self.authData[@"xuid"];
    if (!xuid) {
        return nil;
    }
    
    return [MicrosoftAuthenticator tokenDataOfProfile:xuid];
}

// 修改：设置访问令牌方法，支持离线账号
- (BOOL)setAccessToken:(NSString *)accessToken refreshToken:(NSString *)refreshToken {
    // 如果是离线账号，不保存到钥匙串
    if ([self.authData[@"isOffline"] boolValue]) {
        return YES;
    }
    
    if (!accessToken || !refreshToken) {
        NSLog(@"[MicrosoftAuthenticator] BUG: nil accessToken:%d, refreshToken:%d", !accessToken, !refreshToken);
        return NO;
    }
    
    NSDictionary *tokenDict = @{
        @"accessToken": accessToken,
        @"refreshToken": refreshToken,
    };
    
    NSError *error = nil;
    NSData *data = [NSKeyedArchiver archivedDataWithRootObject:tokenDict requiringSecureCoding:YES error:&error];
    
    if (!data || error) {
        NSLog(@"[MicrosoftAuthenticator] 归档令牌数据失败: %@", error);
        return NO;
    }
    
    NSString *xuid = self.authData[@"xuid"];
    if (!xuid) {
        NSLog(@"[MicrosoftAuthenticator] 无法保存令牌：缺少xuid");
        return NO;
    }
    
    NSDictionary *dict = [MicrosoftAuthenticator keychainQueryForKey:xuid extraInfo:@{
        (id)kSecAttrAccessible: (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        (id)kSecValueData: data
    }];
    
    if (!dict) {
        NSLog(@"[MicrosoftAuthenticator] 无法创建钥匙串查询字典");
        return NO;
    }
    
    // 先删除已存在的项目
    SecItemDelete((__bridge CFDictionaryRef)dict);
    
    // 添加新项目
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)dict, NULL);
    if (status == errSecSuccess) {
        NSLog(@"[MicrosoftAuthenticator] 令牌保存成功");
        return YES;
    } else {
        NSLog(@"[MicrosoftAuthenticator] 令牌保存失败，错误码: %d", (int)status);
        return NO;
    }
}

#pragma mark - 原有的Microsoft认证方法

- (void)acquireAccessToken:(NSString *)authcode refresh:(BOOL)refresh callback:(Callback)callback {
    NSString *progressMsg = localize(@"login.msa.progress.acquireAccessToken", nil);
    if (!progressMsg) {
        progressMsg = @"获取访问令牌...";
    }
    callback(progressMsg, YES);

    NSMutableDictionary *data = [@{
        @"client_id": @"00000000402b5328",
        @"grant_type": refresh ? @"refresh_token" : @"authorization_code",
        @"redirect_url": @"https://login.live.com/oauth20_desktop.srf",
        @"scope": @"service::user.auth.xboxlive.com::MBI_SSL"
    } mutableCopy];
    
    if (refresh) {
        data[@"refresh_token"] = authcode;
    } else {
        data[@"code"] = authcode;
    }

    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    [manager GET:@"https://login.live.com/oauth20_token.srf" parameters:data headers:nil progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        if ([responseObject isKindOfClass:[NSDictionary class]]) {
            NSDictionary *response = (NSDictionary *)responseObject;
            self.authData[@"msaRefreshToken"] = response[@"refresh_token"];
            [self acquireXBLToken:response[@"access_token"] callback:callback];
        } else {
            callback(@"无效的响应格式", NO);
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        if (error.code == NSURLErrorDataNotAllowed) {
            // The account token is expired and offline
            self.authData[@"accessToken"] = @"offline";
            callback(nil, YES);
        } else {
            callback(error, NO);
        }
    }];
}

- (void)acquireXBLToken:(NSString *)accessToken callback:(Callback)callback {
    NSString *progressMsg = localize(@"login.msa.progress.acquireXBLToken", nil);
    if (!progressMsg) {
        progressMsg = @"获取XBL令牌...";
    }
    callback(progressMsg, YES);

    NSDictionary *data = @{
        @"Properties": @{
            @"AuthMethod": @"RPS",
            @"SiteName": @"user.auth.xboxlive.com",
            @"RpsTicket": accessToken ?: @""
        },
        @"RelyingParty": @"http://auth.xboxlive.com",
        @"TokenType": @"JWT"
    };

    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFJSONRequestSerializer serializer];
    [manager POST:@"https://user.auth.xboxlive.com/user/authenticate" parameters:data headers:nil progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        if ([responseObject isKindOfClass:[NSDictionary class]]) {
            NSDictionary *response = (NSDictionary *)responseObject;
            
            __weak typeof(self) weakSelf = self;
            Callback innerCallback = ^(NSString* status, BOOL success) {
                if (!success) {
                    callback(status, NO);
                    return;
                } else if (status) {
                    return;
                }
                // Obtain XSTS for authenticating to Minecraft
                [weakSelf acquireXSTSFor:@"rp://api.minecraftservices.com/" token:response[@"Token"] xstsCallback:^(NSString *xsts, NSString *uhs){
                    if (xsts == nil) {
                        callback(nil, NO);
                        return;
                    }
                    weakSelf.authData[@"xuid"] = uhs;
                    [weakSelf acquireMinecraftToken:uhs xstsToken:xsts callback:callback];
                } callback:callback];
            };

            // Obtain XSTS for getting the Xbox gamertag
            [weakSelf acquireXSTSFor:@"http://xboxlive.com" token:response[@"Token"] xstsCallback:^(NSString *xsts, NSString *uhs){
                if (xsts == nil) {
                    callback(nil, NO);
                    return;
                }
                [weakSelf acquireXboxProfile:uhs xstsToken:xsts callback:innerCallback];
            } callback:callback];
        } else {
            callback(@"无效的XBL响应格式", NO);
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        callback(error, NO);
    }];
}

- (void)acquireXSTSFor:(NSString *)replyingParty token:(NSString *)xblToken xstsCallback:(XSTSCallback)xstsCallback callback:(Callback)callback {
    NSString *progressMsg = localize(@"login.msa.progress.acquireXSTS", nil);
    if (!progressMsg) {
        progressMsg = @"获取XSTS令牌...";
    }
    callback(progressMsg, YES);

    NSDictionary *data = @{
       @"Properties": @{
           @"SandboxId": @"RETAIL",
           @"UserTokens": @[
               xblToken ?: @""
           ]
       },
       @"RelyingParty": replyingParty,
       @"TokenType": @"JWT",
    };

    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFJSONRequestSerializer serializer];
    [manager POST:@"https://xsts.auth.xboxlive.com/xsts/authorize" parameters:data headers:nil progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        if ([responseObject isKindOfClass:[NSDictionary class]]) {
            NSDictionary *response = (NSDictionary *)responseObject;
            NSArray *xui = response[@"DisplayClaims"][@"xui"];
            if ([xui isKindOfClass:[NSArray class]] && xui.count > 0) {
                NSDictionary *firstXui = xui[0];
                if ([firstXui isKindOfClass:[NSDictionary class]]) {
                    NSString *uhs = firstXui[@"uhs"];
                    xstsCallback(response[@"Token"], uhs);
                } else {
                    callback(@"无效的XUI格式", NO);
                }
            } else {
                callback(@"缺少XUI声明", NO);
            }
        } else {
            callback(@"无效的XSTS响应格式", NO);
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        NSString *errorString;
        NSData *errorData = error.userInfo[AFNetworkingOperationFailingURLResponseDataErrorKey];
        if (errorData == nil) {
            callback(error, NO);
            return;
        }
        
        NSError *jsonError;
        NSDictionary *errorDict = [NSJSONSerialization JSONObjectWithData:errorData options:kNilOptions error:&jsonError];
        if (jsonError || ![errorDict isKindOfClass:[NSDictionary class]]) {
            callback(error, NO);
            return;
        }
        
        NSNumber *xerr = errorDict[@"XErr"];
        if (!xerr) {
            errorString = [NSString stringWithFormat:@"%@\n\n响应:\n%@", error.localizedDescription, errorDict];
        } else {
            long xerrValue = [xerr longValue] - 2148916230L;
            switch ((int)xerrValue) {
                case 3:
                    errorString = @"login.msa.error.xsts.noxboxacc";
                    break;
                case 5:
                    errorString = @"login.msa.error.xsts.noxbox";
                    break;
                case 6:
                case 7:
                    errorString = @"login.msa.error.xsts.krverify";
                    break;
                case 8:
                    errorString = @"login.msa.error.xsts.underage";
                    break;
                default:
                    errorString = [NSString stringWithFormat:@"%@\n\nUnknown XErr code, response:\n%@", error.localizedDescription, errorDict];
                    break;
            }
        }
        
        NSString *localizedError = localize(errorString, nil);
        if (!localizedError) {
            localizedError = errorString;
        }
        callback(localizedError, NO);
    }];
}

- (void)acquireXboxProfile:(NSString *)xblUhs xstsToken:(NSString *)xblXsts callback:(Callback)callback {
    NSString *progressMsg = localize(@"login.msa.progress.acquireXboxProfile", nil);
    if (!progressMsg) {
        progressMsg = @"获取Xbox档案...";
    }
    callback(progressMsg, YES);

    NSDictionary *headers = @{
        @"x-xbl-contract-version": @"2",
        @"Authorization": [NSString stringWithFormat:@"XBL3.0 x=%@;%@", xblUhs ?: @"", xblXsts ?: @""]
    };

    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    [manager GET:@"https://profile.xboxlive.com/users/me/profile/settings?settings=PublicGamerpic,Gamertag" parameters:nil headers:headers progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        if ([responseObject isKindOfClass:[NSDictionary class]]) {
            NSDictionary *response = (NSDictionary *)responseObject;
            NSArray *profileUsers = response[@"profileUsers"];
            if ([profileUsers isKindOfClass:[NSArray class]] && profileUsers.count > 0) {
                NSDictionary *firstUser = profileUsers[0];
                if ([firstUser isKindOfClass:[NSDictionary class]]) {
                    NSArray *settings = firstUser[@"settings"];
                    if ([settings isKindOfClass:[NSArray class]] && settings.count >= 2) {
                        NSString *gamerpic = settings[0][@"value"];
                        NSString *gamertag = settings[1][@"value"];
                        
                        if ([gamerpic isKindOfClass:[NSString class]]) {
                            self.authData[@"profilePicURL"] = [NSString stringWithFormat:@"%@&h=120&w=120", gamerpic];
                        }
                        if ([gamertag isKindOfClass:[NSString class]]) {
                            self.authData[@"xboxGamertag"] = gamertag;
                        }
                        callback(nil, YES);
                    } else {
                        callback(@"无效的档案设置格式", NO);
                    }
                } else {
                    callback(@"无效的用户档案格式", NO);
                }
            } else {
                callback(@"未找到用户档案", NO);
            }
        } else {
            callback(@"无效的档案响应格式", NO);
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        callback(error, NO);
    }];
}

- (void)acquireMinecraftToken:(NSString *)xblUhs xstsToken:(NSString *)xblXsts callback:(Callback)callback {
    NSString *progressMsg = localize(@"login.msa.progress.acquireMCToken", nil);
    if (!progressMsg) {
        progressMsg = @"获取Minecraft令牌...";
    }
    callback(progressMsg, YES);

    NSDictionary *data = @{
        @"identityToken": [NSString stringWithFormat:@"XBL3.0 x=%@;%@", xblUhs ?: @"", xblXsts ?: @""]
    };

    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFJSONRequestSerializer serializer];
    [manager POST:@"https://api.minecraftservices.com/authentication/login_with_xbox" parameters:data headers:nil progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        if ([responseObject isKindOfClass:[NSDictionary class]]) {
            NSDictionary *response = (NSDictionary *)responseObject;
            self.authData[@"accessToken"] = response[@"access_token"];
            [self checkMCProfile:response[@"access_token"] callback:callback];
        } else {
            callback(@"无效的Minecraft令牌响应格式", NO);
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        callback(error, NO);
    }];
}

- (void)checkMCProfile:(NSString *)mcAccessToken callback:(Callback)callback {
    self.authData[@"expiresAt"] = @((long)[[NSDate date] timeIntervalSince1970] + 86400);

    NSString *progressMsg = localize(@"login.msa.progress.checkMCProfile", nil);
    if (!progressMsg) {
        progressMsg = @"检查Minecraft档案...";
    }
    callback(progressMsg, YES);

    NSDictionary *headers = @{
        @"Authorization": [NSString stringWithFormat:@"Bearer %@", mcAccessToken ?: @""]
    };
    
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.requestSerializer = [AFJSONRequestSerializer serializer];
    [manager GET:@"https://api.minecraftservices.com/minecraft/profile" parameters:nil headers:headers progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
        if ([responseObject isKindOfClass:[NSDictionary class]]) {
            NSDictionary *response = (NSDictionary *)responseObject;
            NSString *uuid = response[@"id"];
            NSString *name = response[@"name"];
            
            if ([uuid isKindOfClass:[NSString class]] && [name isKindOfClass:[NSString class]]) {
                self.authData[@"profileId"] = [NSString stringWithFormat:@"%@-%@-%@-%@-%@",
                    [uuid substringWithRange:NSMakeRange(0, 8)],
                    [uuid substringWithRange:NSMakeRange(8, 4)],
                    [uuid substringWithRange:NSMakeRange(12, 4)],
                    [uuid substringWithRange:NSMakeRange(16, 4)],
                    [uuid substringWithRange:NSMakeRange(20, 12)]
                ];
                self.authData[@"profilePicURL"] = [NSString stringWithFormat:@"https://mc-heads.net/head/%@/120", self.authData[@"profileId"]];
                self.authData[@"oldusername"] = self.authData[@"username"];
                self.authData[@"username"] = name;
                callback(nil, [self saveChanges]);
            } else {
                callback(@"无效的档案ID或名称", NO);
            }
        } else {
            callback(@"无效的档案响应格式", NO);
        }
    } failure:^(NSURLSessionDataTask *task, NSError *error) {
        NSData *errorData = error.userInfo[AFNetworkingOperationFailingURLResponseDataErrorKey];
        if (errorData) {
            NSError *jsonError;
            NSDictionary *errorDict = [NSJSONSerialization JSONObjectWithData:errorData options:kNilOptions error:&jsonError];
            if (!jsonError && [errorDict isKindOfClass:[NSDictionary class]] && [errorDict[@"error"] isEqualToString:@"NOT_FOUND"]) {
                // If there is no profile, use the Xbox gamertag as username with Demo mode
                NSString *gamertag = self.authData[@"xboxGamertag"];
                if ([gamertag isKindOfClass:[NSString class]]) {
                    self.authData[@"profileId"] = @"00000000-0000-0000-0000-000000000000";
                    self.authData[@"username"] = [NSString stringWithFormat:@"Demo.%@", gamertag];

                    if ([self saveChanges]) {
                        callback(@"DEMO", YES);
                        callback(nil, YES);
                    } else {
                        callback(nil, NO);
                    }
                } else {
                    callback(@"缺少Xbox玩家标签", NO);
                }
                return;
            }
        }

        callback(error, NO);
    }];
}

+ (NSDictionary *)tokenDataOfProfile:(NSString *)profile {
    if (profile && [profile hasPrefix:@"offline_"]) {
        return nil;
    }
    
    NSDictionary *dict = [self keychainQueryForKey:profile extraInfo:@{
        (id)kSecMatchLimit: (id)kSecMatchLimitOne,
        (id)kSecReturnData: (id)kCFBooleanTrue
    }];
    
    if (!dict) {
        return nil;
    }
    
    CFTypeRef result = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)dict, &result);
    if (status == errSecSuccess) {
        NSError *error = nil;
        NSDictionary *tokenData = [NSKeyedUnarchiver unarchivedObjectOfClass:[NSDictionary class] fromData:(__bridge NSData *)result error:&error];
        if (error) {
            NSLog(@"[MicrosoftAuthenticator] 解档令牌数据失败: %@", error);
            return nil;
        }
        return tokenData;
    } else {
        return nil;
    }
}

+ (void)clearTokenDataOfProfile:(NSString *)profile {
    if (profile && [profile hasPrefix:@"offline_"]) {
        return; // 不清理离线账号
    }
    
    NSDictionary *dict = [self keychainQueryForKey:profile extraInfo:nil];
    if (dict) {
        SecItemDelete((__bridge CFDictionaryRef)dict);
    }
}

@end
