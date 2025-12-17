/* eslint-disable no-console,@typescript-eslint/no-explicit-any */
import { NextRequest, NextResponse } from 'next/server';

import { clearConfigCache, getConfig } from '@/lib/config';
import { db } from '@/lib/db';

export const runtime = 'nodejs';

// 读取存储类型环境变量，默认 localstorage
const STORAGE_TYPE =
  (process.env.NEXT_PUBLIC_STORAGE_TYPE as
    | 'localstorage'
    | 'redis'
    | 'upstash'
    | 'kvrocks'
    | undefined) || 'localstorage';

// IP 注册速率限制缓存
interface RateLimitRecord {
  count: number;
  firstAttempt: number;
}
const registerRateLimitCache = new Map<string, RateLimitRecord>();

// 清理过期的速率限制记录
function cleanExpiredRateLimitCache(windowMinutes: number) {
  const now = Date.now();
  const windowMs = windowMinutes * 60 * 1000;
  const expiredIPs: string[] = [];
  registerRateLimitCache.forEach((record, ip) => {
    if (now - record.firstAttempt > windowMs) {
      expiredIPs.push(ip);
    }
  });
  expiredIPs.forEach(ip => registerRateLimitCache.delete(ip));
}


// 获取客户端 IP 地址
function getClientIP(req: NextRequest): string {
  // 优先级：X-Forwarded-For > X-Real-IP > CF-Connecting-IP > 直连IP
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    // X-Forwarded-For 可能包含多个IP，取第一个
    return forwarded.split(',')[0].trim();
  }

  const realIP = req.headers.get('x-real-ip');
  if (realIP) {
    return realIP.trim();
  }

  const cfIP = req.headers.get('cf-connecting-ip');
  if (cfIP) {
    return cfIP.trim();
  }

  // 如果都没有，返回未知
  return 'unknown';
}

// 检查 IP 速率限制
function checkRateLimit(ip: string, maxCount: number, windowMinutes: number): { allowed: boolean; remainingTime?: number } {
  const now = Date.now();
  const windowMs = windowMinutes * 60 * 1000;

  // 先清理过期记录
  cleanExpiredRateLimitCache(windowMinutes);

  const record = registerRateLimitCache.get(ip);

  if (!record) {
    // 新IP，记录第一次尝试
    registerRateLimitCache.set(ip, { count: 1, firstAttempt: now });
    return { allowed: true };
  }

  // 检查是否在时间窗口内
  if (now - record.firstAttempt > windowMs) {
    // 时间窗口已过，重置记录
    registerRateLimitCache.set(ip, { count: 1, firstAttempt: now });
    return { allowed: true };
  }

  // 在时间窗口内，检查次数
  if (record.count >= maxCount) {
    const remainingTime = Math.ceil((windowMs - (now - record.firstAttempt)) / 60000);
    return { allowed: false, remainingTime };
  }

  // 增加计数
  record.count++;
  return { allowed: true };
}

// 生成签名
async function generateSignature(
  data: string,
  secret: string
): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(data);

  // 导入密钥
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // 生成签名
  const signature = await crypto.subtle.sign('HMAC', key, messageData);

  // 转换为十六进制字符串
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// 生成认证Cookie（带签名）
async function generateAuthCookie(
  username?: string,
  password?: string,
  role?: 'owner' | 'admin' | 'user',
  includePassword = false
): Promise<string> {
  const authData: any = { role: role || 'user' };

  // 只在需要时包含 password
  if (includePassword && password) {
    authData.password = password;
  }

  if (username && process.env.PASSWORD) {
    authData.username = username;
    // 使用密码作为密钥对用户名进行签名
    const signature = await generateSignature(username, process.env.PASSWORD);
    authData.signature = signature;
    authData.timestamp = Date.now(); // 添加时间戳防重放攻击
  }

  return encodeURIComponent(JSON.stringify(authData));
}

export async function POST(req: NextRequest) {
  try {
    // localStorage 模式不支持注册
    if (STORAGE_TYPE === 'localstorage') {
      return NextResponse.json(
        { error: 'localStorage 模式不支持用户注册' },
        { status: 400 }
      );
    }

    const { username, password, confirmPassword } = await req.json();

    // 先检查配置中是否允许注册（在验证输入之前）
    let config;
    try {
      config = await getConfig();
      const allowRegister = config.UserConfig?.AllowRegister !== false; // 默认允许注册

      if (!allowRegister) {
        return NextResponse.json(
          { error: '管理员已关闭用户注册功能' },
          { status: 403 }
        );
      }

      // 检查 IP 速率限制
      const rateLimitEnabled = config.UserConfig?.RegisterRateLimitEnabled === true;
      if (rateLimitEnabled) {
        const clientIP = getClientIP(req);
        const maxCount = config.UserConfig?.RegisterRateLimitPerIP || 3;
        const windowMinutes = config.UserConfig?.RegisterRateLimitMinutes || 60;

        const rateLimitResult = checkRateLimit(clientIP, maxCount, windowMinutes);
        if (!rateLimitResult.allowed) {
          return NextResponse.json(
            { error: `注册过于频繁，请在 ${rateLimitResult.remainingTime} 分钟后再试` },
            { status: 429 }
          );
        }
      }
    } catch (err) {
      console.error('检查注册配置失败', err);
      return NextResponse.json({ error: '注册失败，请稍后重试' }, { status: 500 });
    }

    // 验证输入
    if (!username || typeof username !== 'string' || username.trim() === '') {
      return NextResponse.json({ error: '用户名不能为空' }, { status: 400 });
    }

    if (!password || typeof password !== 'string') {
      return NextResponse.json({ error: '密码不能为空' }, { status: 400 });
    }

    if (password !== confirmPassword) {
      return NextResponse.json({ error: '两次输入的密码不一致' }, { status: 400 });
    }

    if (password.length < 6) {
      return NextResponse.json({ error: '密码长度至少6位' }, { status: 400 });
    }

    // 检查是否与管理员用户名冲突
    if (username === process.env.USERNAME) {
      return NextResponse.json({ error: '该用户名已被使用' }, { status: 400 });
    }

    // 检查用户名格式（只允许字母数字和下划线）
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return NextResponse.json(
        { error: '用户名只能包含字母、数字和下划线，长度3-20位' },
        { status: 400 }
      );
    }

    try {
      // 检查用户是否已存在
      const userExists = await db.checkUserExist(username);
      if (userExists) {
        return NextResponse.json({ error: '该用户名已被注册' }, { status: 400 });
      }

      // 注册用户
      await db.registerUser(username, password);

      // 获取客户端 IP
      const clientIP = getClientIP(req);

      // 检查是否需要审核（使用之前获取的 config）
      const requireApproval = config?.UserConfig?.RequireApproval === true;

      const newUser: {
        username: string;
        role: 'user';
        createdAt: number;
        registerIP?: string;
        pendingApproval?: boolean;
      } = {
        username: username,
        role: 'user' as const,
        createdAt: Date.now(), // 设置注册时间戳
        registerIP: clientIP, // 记录注册 IP
      };

      // 如果需要审核，标记为待审核状态
      if (requireApproval) {
        newUser.pendingApproval = true;
      }

      // 刷新配置再添加用户
      const latestConfig = await getConfig();
      latestConfig.UserConfig.Users.push(newUser);

      // 保存更新后的配置
      await db.saveAdminConfig(latestConfig);

      // 清除缓存，确保下次获取配置时是最新的
      clearConfigCache();

      // 如果需要审核，返回等待审核提示，不设置登录cookie
      if (requireApproval) {
        return NextResponse.json({
          ok: true,
          pendingApproval: true,
          message: '注册申请已提交，请等待管理员审核'
        });
      }

      // 不需要审核时，注册成功后自动登录
      const response = NextResponse.json({
        ok: true,
        message: '注册成功，已自动登录'
      });

      const cookieValue = await generateAuthCookie(
        username,
        password,
        'user',
        false
      );
      const expires = new Date();
      expires.setDate(expires.getDate() + 7); // 7天过期

      response.cookies.set('auth', cookieValue, {
        path: '/',
        expires,
        sameSite: 'lax',
        httpOnly: false,
        secure: false,
      });

      return response;
    } catch (err) {
      console.error('注册用户失败', err);
      return NextResponse.json({ error: '注册失败，请稍后重试' }, { status: 500 });
    }
  } catch (error) {
    console.error('注册接口异常', error);
    return NextResponse.json({ error: '服务器错误' }, { status: 500 });
  }
}