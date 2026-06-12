import {
  LockOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons';
import {
  FormattedMessage,
  Helmet,
  SelectLang,
  useIntl,
  useModel,
} from '@umijs/max';
import { Alert, App, Button, Checkbox, Divider, Form, Input } from 'antd';
import { createStyles } from 'antd-style';
import React, { useState } from 'react';
import { flushSync } from 'react-dom';
import loginBg from '@/assets/login-bg.png';
import { DEFAULT_INITIAL_PASSWORD } from '@/constants/auth';
import {
  ARGUS_MUST_CHANGE_PASSWORD_KEY,
  ARGUS_TOKEN_KEY,
  ARGUS_USER_KEY,
} from '@/constants/storage';
import { isDemoMode } from '@/demo';
import { loginApiAuthLoginPost as login } from '@/services/swagger/auth';
import Settings from '../../../../config/defaultSettings';
import DotGridBackground from './DotGridBackground';

const useStyles = createStyles(({ token }) => ({
  page: {
    position: 'relative',
    display: 'flex',
    flexDirection: 'column',
    minHeight: '100vh',
    overflow: 'hidden',
    background: '#f8faff',
  },
  pageBg: {
    position: 'absolute',
    inset: 0,
    zIndex: 0,
    backgroundImage: `url(${loginBg})`,
    backgroundRepeat: 'no-repeat',
    backgroundSize: 'cover',
    backgroundPosition: 'left center',
    pointerEvents: 'none',
    '@media (max-width: 992px)': {
      backgroundPosition: 'center top',
    },
  },
  header: {
    position: 'relative',
    zIndex: 2,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '24px 40px',
  },
  brand: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
  },
  brandLogo: {
    width: 36,
    height: 36,
    objectFit: 'contain',
  },
  brandName: {
    margin: 0,
    fontSize: 20,
    fontWeight: 700,
    color: '#1a1a2e',
    letterSpacing: '-0.02em',
  },
  lang: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    padding: '6px 12px',
    borderRadius: 8,
    color: token.colorTextSecondary,
    cursor: 'pointer',
    transition: 'background 0.2s',
    ':hover': {
      background: 'rgba(0, 0, 0, 0.04)',
    },
  },
  main: {
    position: 'relative',
    zIndex: 1,
    display: 'flex',
    flex: 1,
    minHeight: 0,
    alignItems: 'center',
    justifyContent: 'flex-end',
    padding: '0 clamp(24px, 8vw, 120px) 48px',
    '@media (max-width: 992px)': {
      justifyContent: 'center',
      padding: '280px 24px 48px',
    },
  },
  formSection: {
    position: 'relative',
    flex: '0 0 auto',
    width: '100%',
    maxWidth: 420,
    '@media (max-width: 992px)': {
      maxWidth: 420,
    },
  },
  dotGrid: {
    position: 'absolute',
    right: 0,
    bottom: 0,
    width: '55%',
    height: '45%',
    pointerEvents: 'none',
    opacity: 0.65,
    maskImage: 'linear-gradient(135deg, transparent 20%, black 70%)',
    WebkitMaskImage: 'linear-gradient(135deg, transparent 20%, black 70%)',
  },
  card: {
    width: '100%',
    maxWidth: 420,
    padding: '40px 36px 28px',
    background: '#fff',
    borderRadius: 16,
    boxShadow:
      '0 4px 24px rgba(15, 23, 42, 0.06), 0 1px 3px rgba(15, 23, 42, 0.04)',
  },
  title: {
    margin: '0 0 8px',
    fontSize: 28,
    fontWeight: 700,
    color: '#1a1a2e',
    lineHeight: 1.3,
  },
  subtitle: {
    margin: '0 0 32px',
    fontSize: 14,
    color: token.colorTextSecondary,
    lineHeight: 1.5,
  },
  fieldGroup: {
    marginBottom: 20,
  },
  fieldLabel: {
    display: 'block',
    marginBottom: 2,
    fontSize: 12,
    fontWeight: 500,
    color: token.colorTextSecondary,
    lineHeight: '18px',
  },
  input: {
    height: 48,
    borderRadius: 10,
    borderColor: '#e5e9f0',
    '&:hover, &:focus': {
      borderColor: token.colorPrimary,
    },
  },
  optionsRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 24,
  },
  forgotLink: {
    fontSize: 14,
    color: token.colorPrimary,
    cursor: 'pointer',
    ':hover': {
      opacity: 0.85,
    },
  },
  submitBtn: {
    height: 48,
    borderRadius: 10,
    border: 'none',
    fontSize: 16,
    fontWeight: 600,
    background: 'linear-gradient(90deg, #3b82f6 0%, #7c3aed 100%)',
    boxShadow: '0 4px 14px rgba(59, 130, 246, 0.35)',
    ':hover': {
      background: 'linear-gradient(90deg, #2563eb 0%, #6d28d9 100%) !important',
      boxShadow: '0 6px 18px rgba(59, 130, 246, 0.4)',
    },
  },
  divider: {
    margin: '28px 0 20px',
    color: token.colorTextQuaternary,
    fontSize: 13,
    '&::before, &::after': {
      borderColor: '#e8ecf2 !important',
    },
  },
  ssoBtn: {
    height: 48,
    borderRadius: 10,
    borderColor: '#e5e9f0',
    fontSize: 15,
    fontWeight: 500,
    color: '#334155',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    ':hover': {
      borderColor: `${token.colorPrimary} !important`,
      color: `${token.colorPrimary} !important`,
    },
  },
  copyright: {
    marginTop: 28,
    textAlign: 'center',
    fontSize: 12,
    color: token.colorTextQuaternary,
    lineHeight: 1.5,
  },
}));

const Lang = () => {
  const { styles } = useStyles();
  return (
    <div className={styles.lang} data-lang>
      {SelectLang && <SelectLang />}
    </div>
  );
};

const LoginMessage: React.FC<{ content: string }> = ({ content }) => (
  <Alert style={{ marginBottom: 24 }} message={content} type="error" showIcon />
);

const Login: React.FC = () => {
  const [userLoginState, setUserLoginState] = useState<
    Partial<API.LoginResponse> & { message?: string }
  >({});
  const [form] = Form.useForm<API.LoginRequest & { autoLogin?: boolean }>();
  const { initialState, setInitialState } = useModel('@@initialState');
  const { styles } = useStyles();
  const { message } = App.useApp();
  const intl = useIntl();

  const handleSubmit = async (values: API.LoginRequest) => {
    try {
      const msg = await login(values);
      if (msg.success && msg.token) {
        const currentUser: API.CurrentUser = {
          id: 'local-session',
          username: msg.username,
          display_name: msg.display_name || msg.username,
          is_active: true,
          is_superuser: false,
        };
        localStorage.setItem(ARGUS_TOKEN_KEY, msg.token);
        localStorage.setItem(ARGUS_USER_KEY, JSON.stringify(currentUser));
        const isInitialPassword = values.password === DEFAULT_INITIAL_PASSWORD;
        if (isInitialPassword) {
          localStorage.setItem(ARGUS_MUST_CHANGE_PASSWORD_KEY, '1');
        } else {
          localStorage.removeItem(ARGUS_MUST_CHANGE_PASSWORD_KEY);
        }
        const defaultLoginSuccessMessage = intl.formatMessage({
          id: 'pages.login.success',
          defaultMessage: isInitialPassword
            ? '登录成功，请修改初始密码'
            : '登录成功！',
        });
        message.success(defaultLoginSuccessMessage);
        flushSync(() => {
          setInitialState({
            ...initialState,
            currentUser,
          });
        });
        const urlParams = new URL(window.location.href).searchParams;
        window.location.href = urlParams.get('redirect') || '/';
        return;
      }
      setUserLoginState(msg);
    } catch (error) {
      const defaultLoginFailureMessage = intl.formatMessage({
        id: 'pages.login.failure',
        defaultMessage: '登录失败，请重试！',
      });
      message.error(defaultLoginFailureMessage);
    }
  };

  const { success } = userLoginState;

  return (
    <div className={styles.page}>
      <div className={styles.pageBg} aria-hidden />
      <Helmet>
        <title>
          {intl.formatMessage({
            id: 'menu.login',
            defaultMessage: '登录页',
          })}
          {Settings.title && ` - ${Settings.title}`}
        </title>
      </Helmet>

      <header className={styles.header}>
        <div className={styles.brand}>
          <img
            className={styles.brandLogo}
            src={Settings.logo}
            alt="Argus Mind"
          />
          <h1 className={styles.brandName}>Argus Mind</h1>
        </div>
        <Lang />
      </header>

      <main className={styles.main}>
        <section className={styles.formSection}>
          <div className={styles.dotGrid}>
            <DotGridBackground />
          </div>

          <div className={styles.card}>
            <h2 className={styles.title}>
              {intl.formatMessage({
                id: 'pages.login.welcome',
                defaultMessage: '欢迎回来 👋',
              })}
            </h2>
            <p className={styles.subtitle}>
              {intl.formatMessage({
                id: 'pages.login.subtitle',
                defaultMessage: '登录 Argus Mind AI代码审计平台',
              })}
            </p>

            {isDemoMode() && (
              <Alert
                style={{ marginBottom: 24 }}
                type="info"
                showIcon
                message={intl.formatMessage({
                  id: 'pages.login.demoHint',
                  defaultMessage: '演示环境：默认账号 admin，密码 admin',
                })}
              />
            )}

            <Form
              form={form}
              layout="vertical"
              requiredMark={false}
              initialValues={{ autoLogin: true }}
              onFinish={async (values) => {
                const { autoLogin: _autoLogin, ...loginValues } = values;
                await handleSubmit(loginValues);
              }}
            >
              {success === false && (
                <LoginMessage
                  content={userLoginState.message || '用户名或密码错误'}
                />
              )}

              <div className={styles.fieldGroup}>
                <span className={styles.fieldLabel}>
                  {intl.formatMessage({
                    id: 'pages.login.username.label',
                    defaultMessage: '用户名',
                  })}
                </span>
                <Form.Item
                  name="username"
                  noStyle
                  rules={[
                    { required: true, message: '请输入用户名' },
                    {
                      min: 1,
                      max: 64,
                      message: intl.formatMessage({
                        id: 'pages.login.username.required',
                        defaultMessage: '请输入 1-64 位用户名',
                      }),
                    },
                  ]}
                >
                  <Input
                    size="large"
                    className={styles.input}
                    prefix={<UserOutlined style={{ color: '#94a3b8' }} />}
                    placeholder={intl.formatMessage({
                      id: 'pages.login.username.placeholder',
                      defaultMessage: '请输入用户名',
                    })}
                  />
                </Form.Item>
              </div>

              <div className={styles.fieldGroup} style={{ marginBottom: 16 }}>
                <span className={styles.fieldLabel}>
                  {intl.formatMessage({
                    id: 'pages.login.password.label',
                    defaultMessage: '密码',
                  })}
                </span>
                <Form.Item
                  name="password"
                  noStyle
                  rules={[
                    {
                      required: true,
                      message: intl.formatMessage({
                        id: 'pages.login.password.required',
                        defaultMessage: '请输入密码',
                      }),
                    },
                  ]}
                >
                  <Input.Password
                    size="large"
                    className={styles.input}
                    prefix={<LockOutlined style={{ color: '#94a3b8' }} />}
                    placeholder={intl.formatMessage({
                      id: 'pages.login.password.placeholder',
                      defaultMessage: '请输入密码',
                    })}
                  />
                </Form.Item>
              </div>

              <div className={styles.optionsRow}>
                <Form.Item name="autoLogin" valuePropName="checked" noStyle>
                  <Checkbox>
                    <FormattedMessage
                      id="pages.login.rememberMe"
                      defaultMessage="自动登录"
                    />
                  </Checkbox>
                </Form.Item>
                <a
                  className={styles.forgotLink}
                  onClick={(e) => {
                    e.preventDefault();
                    message.info(
                      intl.formatMessage({
                        id: 'pages.login.forgotPasswordHint',
                        defaultMessage: '请联系管理员重置密码',
                      }),
                    );
                  }}
                >
                  <FormattedMessage
                    id="pages.login.forgotPassword"
                    defaultMessage="忘记密码?"
                  />
                </a>
              </div>

              <Form.Item style={{ marginBottom: 0 }}>
                <Button
                  type="primary"
                  htmlType="submit"
                  block
                  className={styles.submitBtn}
                >
                  <FormattedMessage
                    id="pages.login.submit"
                    defaultMessage="登录"
                  />
                </Button>
              </Form.Item>
            </Form>
            <p className={styles.copyright}>
              © {new Date().getFullYear()} Argus Mind. All rights reserved.
            </p>
          </div>
        </section>
      </main>
    </div>
  );
};

export default Login;
