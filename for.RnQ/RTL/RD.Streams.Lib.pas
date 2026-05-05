unit RD.Streams.Lib;
{$I forRnQConfig.inc}
{$I NoRTTI.inc}

interface

uses
  Classes,
  RDGlobal
  ;

type
  TarchiveStream = class(Tstream)
  protected
    pos, cachedTotal: int64;
    cur: integer;
    aHTTPHeader: RawByteString;
    procedure invalidate();
    procedure calculate(); virtual; abstract;
    function getTotal(): int64; Virtual; // Not always can calculate total size
  public
    flist: array of record
      src,          // full path of the file on the disk
      dst: string;  // full path of the file in the archive
      HDRfirstByte,    // offset of the file META Info inside the archive
      dataFirstByte,   // offset of the file DATA inside the archive
//      mtime,
      size: int64;
      fTime: TDateTime;
      data: Tobject;  // extra data
     end;
    onDestroy: TNotifyEvent;

    constructor Create;
    destructor  Destroy; override;
    function   addFile(const src: string; dst: string=''; data: Tobject=NIL): boolean; virtual;
    function   count(): integer;
    procedure  reset(); virtual;
    property   totalSize: int64 read getTotal;
    property   current: integer read cur;
  end; // TarchiveStream

implementation

uses
  Windows, SysUtils, StrUtils, DateUtils, math,
{$IFDEF UNICODE}
  AnsiStrings,
{$ENDIF UNICODE}
//  RDFileUtil,
  RDUtils
;

//////////// TarchiveStream

function TarchiveStream.getTotal():int64;
begin
  if cachedTotal < 0 then
    calculate();
  result := cachedTotal;
end; // getTotal

function TarchiveStream.addFile(const src: string; dst: string=''; data: Tobject=NIL): boolean;

  function getMtime(fh: Thandle): int64;
  var
    ctime, atime, mtime: Tfiletime;
    st: TSystemTime;
  begin
    getFileTime(fh, @ctime, @atime, @mtime);
    fileTimeToSystemTime(mtime, st);
    result := dateTimeToUnix(SystemTimeToDateTime(st));
  end; // getMtime

  function getFtime(fh: Thandle): TDateTime;
  var
    ctime, atime, mtime: Tfiletime;
    st: TSystemTime;
  begin
    getFileTime(fh, @ctime, @atime, @mtime);
    fileTimeToSystemTime(mtime, st);
    Result := SystemTimeToDateTime(st);
  end; // getFTime
var
  i, fh: integer;
begin
  result := FALSE;
  fh := fileopen(src, fmOpenRead+fmShareDenyNone);
  if fh = -1 then
    exit;
  result := TRUE;
  if dst = '' then
    dst := extractFileName(src);
  i := length(flist);
  setLength(flist, i+1);
  flist[i].fTime := getFtime(fh);
//  flist[i].mtime := getMtime(fh);
  fileClose(fh);
  flist[i].src := src;
  flist[i].dst := dst;
  flist[i].data := data;
  flist[i].size := sizeOfFile(src);
  flist[i].HDRfirstByte := -1;
  flist[i].DatafirstByte := -1;
  invalidate();
end; // addFile

procedure TarchiveStream.invalidate();
begin
  cachedTotal := -1
end;

constructor TarchiveStream.create;
begin
  inherited;
  reset();
end; // create

destructor TarchiveStream.destroy;
begin
  if assigned(onDestroy) then
    onDestroy(self);
  inherited;
end; // destroy

procedure TarchiveStream.reset();
begin
  flist := NIL;
  cur := 0;
  pos := 0;
  invalidate();
end; // reset

function TarchiveStream.count(): integer;
begin
  result := length(flist)
end;


end.
