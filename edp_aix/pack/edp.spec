### 0.define section                                #自定义宏段，这个不是必须的
### %define nginx_user nginx                        #这是我们自定义了一个宏，名字为nginx_user值为nginx，%{nginx_user}引用
### 1.The introduction section                      #介绍区域段
Name:           edp_vrv                             #名字为tar包的名字
Version:        1.0.0.2                             #版本号，一定要与tar包的一致哦
Release:        aix                                 #释出号，也就是第几次制作rpm
Summary:        edp rpm package for aix             #软件包简介，最好不要超过50字符

Group:          System Environment/Daemons          #组名，可以通过less /usr/share/doc/rpm-4.8.0/GROUPS 选择合适组
License:        GPLv2                               #许可，GPL还是BSD等
URL:            http://www.vrv.com.cn               #可以写一个网址
Packager:       hsin2code <hsin2code@gmail.com>
Vendor:         vrv.com.cn
Source:         %{name}-%{version}.tar
#定义用到的source，也就是你收集的，可以用宏来表示，也可以直接写名字，上面定义的内容都可以像上面那样引用
#patch0:            a.patch                 #如果需要补丁，依次写
#BuildRoot:      %_topdir/BUILDROOT
#这个是软件make install 的测试安装目录，也就是测试中的根，我们不用默认的，我们自定义，
#我们可以来观察生成了哪此文件，方便写file区域
#BuildRequires:  gcc,make                           #制作过程中用到的软件包
#Requires:       pcre,pcre-devel,openssl,chkconfig  #软件运行需要的软件包，也可以指定最低版本如 bash >= 1.1.1
%description                                        #软件包描述，尽情的写吧
It is a management of hosts monitoring and auditing.#描述内容

###  2.The Prep section 准备阶段,主要目的解压source并cd进去

%prep                                               #这个宏开始
#%setup -q                                          #这个宏的作用静默模式解压并cd
#%patch0 -p1                                        #如果需要在这打补丁，依次写
rm -rf $RPM_BUILD_DIR/edp_vrv
tar xvf $RPM_SOURCE_DIR/edp_vrv.tar

###  3.The Build Section 编译制作阶段，主要目的就是编译
%build
#./configure \                                      #./configure 也可以用%configure来替换
#--prefix=/usr \                                    #下面的我想大家都很熟悉
#--sbin-path=/usr/sbin/nginx \
#make %{?_smp_mflags}                               #make后面的意思是：如果就多处理器的话make时并行编译
chomd +x $RPM_BUILD_DIR/edp_vrv/bin/edp_client

###  4.Install section  安装阶段
%install
#rm -rf %{buildroot}                                 #先删除原来的安装的，如果你不是第一次安装的话
#make install DESTDIR=%{buildroot}                   #DESTDIR指定安装的目录，而不是真实的安装目录，
                                                    #%{buildroot}你应该知道是指的什么了
mkdir $RPM_BUILD_ROOT/opt
cp -rf edp_vrv $RPM_BUILD_ROOT/opt/
###  4.1 scripts section #没必要可以不写
%pre                                                #rpm安装前制行的脚本
#if [ $1 == 1 ];then                                #$1==1 代表的是第一次安装，2代表是升级，0代表是卸载
#    /usr/sbin/useradd -r nginx 2> /dev/null        #其实这个脚本写的不完整
#fi
%post                                               #安装后执行的脚本

%preun      #卸载前执行的脚本
#if [ $1 == 0 ];then
#    /usr/sbin/userdel -r nginx 2> /dev/null
#fi
%postun     #卸载后执行的脚本

###  5.clean section 清理段,删除buildroot
%clean
rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/*

###  6.file section 要包含的文件
%files
%defattr (-,root,root,0755)                         #设定默认权限，如果下面没有指定权限，则继承默认
/opt/                                               #下面的内容要根据你在%{rootbuild}下生成的来写

###  7.chagelog section  改变日志段
%changelog
*  Fri Aug 5 2016 laoguang <hsin2code@gmail.com> - 1.0.0.1-1
#- Initial version
